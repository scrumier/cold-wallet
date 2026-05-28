use bip39::Mnemonic;

use crate::base64;
use crate::crypto::{self, KEY_LEN, NONCE_LEN, SALT_LEN};
use crate::derive::{indices_to_entropy, taproot_address};
use crate::keyboard::{passphrase_key_at, KeyPress};
use crate::layout::*;
use crate::psbt::{self, ParsedPsbt, MAX_PSBT_RAW};
use crate::signing::sign_psbt;
use crate::storage::{
    DiskHeader, PERSIST_BYTES, Secrets, encrypt_into_blob, try_decrypt, update_lockout,
};

// Lock the wallet permanently after this many consecutive wrong PIN attempts.
pub const PIN_MAX_ATTEMPTS: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PinGate {
    Unlock,
    ShowMnemonic,
    ChangePin,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AppState {
    Welcome,
    NewWallet        { page: u8 },
    RestoreWallet {
        word_idx:  u8,
        buf:       [u8; 8],   // lowercase ASCII prefix typed so far
        buf_len:   u8,
        confirmed: [u16; 24], // BIP39 word indices for each confirmed word
        error:     bool,      // true when the last 24-word set failed BIP39 checksum
    },
    EnterPassphrase  { buf: [u8; 32], len: u8 },
    SetPin           { order: [u8; 10], digits: [u8; 6], len: u8 },
    ConfirmPin       { pin: [u8; 6], order: [u8; 10], digits: [u8; 6], len: u8 },
    PinMismatch,
    EnterPin         { order: [u8; 10], digits: [u8; 6], len: u8, gate: PinGate },
    /// Intermediate state: 6th PIN digit just entered, write-ahead persist
    /// already done, but the slow PBKDF2 + AEAD decryption hasn't run yet.
    /// Drawn as "Verifying PIN…" so the user has feedback during the ~500ms
    /// (release) / ~2-3s (debug) KDF. Resolved by `process_pending`.
    PinVerifying     { digits: [u8; 6], gate: PinGate },
    /// Intermediate state: ConfirmPin matched, but the slow PBKDF2 +
    /// encryption pass hasn't run yet. Drawn as "Saving wallet…".
    PinConfirming    { new_pin: [u8; 6] },
    /// Permanent lockout after PIN_MAX_ATTEMPTS wrong attempts.
    PinLocked,
    Home,
    Receive,
    SignScan,
    SignReview,
    SignResult,
    Accounts,
    Settings,
    ShowMnemonic     { page: u8 },
    About,
}

// PsbtScanned carries 512 bytes; boxing would require alloc which we don't have in no_std.
#[allow(clippy::large_enum_variant)]
pub enum WalletEvent {
    Touch { x: i32, y: i32, entropy: [u8; 32] },
    /// A PSBT QR code was successfully decoded by the camera / simulator.
    /// `data` is the raw Base64-encoded PSBT; `len` is the number of valid bytes.
    PsbtScanned { data: [u8; 512], len: usize },
}

/// Max byte length of a Base64-encoded signed PSBT we'll display as a QR.
const MAX_SIGNED_B64: usize = 1024;

pub struct ColdWallet {
    pub state:          AppState,
    pin:                Option<[u8; 6]>,
    words:              [&'static str; 24],
    entropy:            [u8; 32],
    /// BIP39 seed (64 bytes). Stored so we can sign without re-asking the passphrase.
    seed:               [u8; 64],
    address:            [u8; 62],
    /// Currently loaded PSBT (set on PsbtScanned, cleared on Home).
    psbt:               Option<ParsedPsbt>,
    /// Base64 of the signed PSBT, for QR display on SignResult screen.
    signed_psbt_b64:    [u8; MAX_SIGNED_B64],
    signed_psbt_b64_len: usize,

    // ── At-rest encryption + lockout state ────────────────────────────────
    /// Per-wallet salt. Generated on initial PIN confirmation, persisted in the
    /// disk header. Zero before initial setup.
    salt:               [u8; SALT_LEN],
    /// PBKDF2-derived encryption key, cached after a successful unlock or after
    /// initial setup. Kept in RAM so we can re-encrypt without re-running the
    /// 600k-iteration KDF. `None` before the wallet is unlocked.
    enc_key:            Option<[u8; KEY_LEN]>,
    /// Consecutive wrong-PIN attempts, mirrored to the on-disk header so the
    /// counter survives a power cycle (no brute-force-by-restart).
    pub(crate) failures: u8,
    /// Permanent lockout flag, also mirrored to disk.
    pub(crate) locked:   bool,
    /// Latest on-disk image. `None` before the wallet has been persisted (i.e.
    /// during initial setup, before ConfirmPin succeeds).
    disk_image:         Option<[u8; PERSIST_BYTES]>,
    /// Set to `true` when `load_psbt` fails to decode or parse the scanned QR.
    /// Cleared on a successful parse and when leaving SignScan. The draw layer
    /// can read this via `scan_error()` to show a "PSBT rejected — rescan" hint.
    scan_error_flag:    bool,
}

impl ColdWallet {
    pub fn new() -> Self {
        Self {
            state:              AppState::Welcome,
            pin:                None,
            words:              [""; 24],
            entropy:            [0u8; 32],
            seed:               [0u8; 64],
            address:            [0u8; 62],
            psbt:               None,
            signed_psbt_b64:    [0u8; MAX_SIGNED_B64],
            signed_psbt_b64_len: 0,
            salt:               [0u8; SALT_LEN],
            enc_key:            None,
            failures:           0,
            locked:             false,
            disk_image:         None,
            scan_error_flag:    false,
        }
    }

    pub fn get_state(&self) -> AppState { self.state }

    pub fn mnemonic_words(&self) -> &[&'static str; 24] { &self.words }

    /// Returns the derived P2TR address, or `None` if not yet derived.
    pub fn receive_address(&self) -> Option<&str> {
        if self.address[0] == b'b' {
            core::str::from_utf8(&self.address).ok()
        } else {
            None
        }
    }

    /// Returns the x-only BIP86 internal key derived from the stored seed, if available.
    /// Used by the simulator to build test PSBTs without exposing the private key.
    pub fn tap_internal_key(&self) -> Option<[u8; 32]> {
        if self.seed == [0u8; 64] { return None; }
        crate::derive::tap_keypair(&self.seed).map(|(ik, _)| ik)
    }

    /// Returns the x-only *tweaked* output key — i.e. the 32-byte witness
    /// program that appears in our own P2TR scriptPubKeys. Used by the sign-
    /// review screen to identify change outputs without trusting PSBT
    /// metadata.
    pub fn tap_output_key(&self) -> Option<[u8; 32]> {
        let ik = self.tap_internal_key()?;
        crate::derive::taproot_tweak_pub(&ik)
    }

    /// Returns the currently loaded PSBT, if any.
    pub fn current_psbt(&self) -> Option<&ParsedPsbt> { self.psbt.as_ref() }

    /// Current on-disk image. `None` if the wallet has never been persisted.
    pub fn disk_image(&self) -> Option<&[u8; PERSIST_BYTES]> { self.disk_image.as_ref() }

    /// `true` iff the last `PsbtScanned` event was rejected (bad base64 or
    /// invalid PSBT). Cleared on a successful parse and when leaving SignScan.
    /// The draw layer reads this to show a "PSBT rejected — rescan" hint.
    pub fn scan_error(&self) -> bool { self.scan_error_flag }

    /// Boots a wallet from a previously written disk image. The wallet starts
    /// in `EnterPin { gate: Unlock }` — or in `PinLocked` if the header says so.
    /// `shuffle_entropy` is fresh entropy used only to randomise the PIN pad order.
    pub fn from_disk_image(image: [u8; PERSIST_BYTES], shuffle_entropy: [u8; 32]) -> Option<Self> {
        let hdr = DiskHeader::parse(&image).ok()?;
        let mut w = Self::new();
        w.salt       = hdr.salt;
        w.failures   = hdr.failures;
        w.locked     = hdr.locked;
        w.disk_image = Some(image);
        w.state = if hdr.locked {
            AppState::PinLocked
        } else {
            AppState::EnterPin {
                order:  shuffle(&shuffle_entropy),
                digits: [0u8; 6], len: 0,
                gate:   PinGate::Unlock,
            }
        };
        Some(w)
    }

    /// Returns the signed PSBT as a Base64 string, if signing has completed.
    pub fn signed_psbt_b64(&self) -> Option<&str> {
        if self.signed_psbt_b64_len > 0 {
            core::str::from_utf8(&self.signed_psbt_b64[..self.signed_psbt_b64_len]).ok()
        } else {
            None
        }
    }

    /// Drives the state machine in response to a UI/QR event.
    ///
    /// `persist` is invoked with the current on-disk image whenever the wallet
    /// needs to be written (PIN attempt write-ahead, successful unlock,
    /// initial setup, PIN change). The caller (simulator / hardware crate) is
    /// responsible for atomic disk writes.
    pub fn handle_event<F>(&mut self, event: WalletEvent, persist: &mut F)
    where
        F: FnMut(&[u8; PERSIST_BYTES]),
    {
        // Capture entropy before the event is consumed by step().
        let touch_entropy = match &event {
            WalletEvent::Touch { entropy, .. } => *entropy,
            WalletEvent::PsbtScanned { .. } => [0u8; 32],
        };

        match event {
            WalletEvent::PsbtScanned { data, len } => {
                if matches!(self.state, AppState::SignScan) {
                    self.load_psbt(&data[..len]);
                }
                return;
            }
            WalletEvent::Touch { .. } => {}
        }

        let prev = self.state;
        let (new_state, new_pin, new_words, new_entropy) = step(self.state, event, self.pin);
        self.state = new_state;
        if let Some(p) = new_pin     { self.pin     = Some(p); }
        if let Some(w) = new_words   { self.words   = w; }
        if let Some(e) = new_entropy { self.entropy = e; }

        // Derive seed + address when the passphrase step is finalised.
        if let AppState::EnterPassphrase { buf, len } = prev
            && matches!(self.state, AppState::SetPin { .. })
        {
            let pp = core::str::from_utf8(&buf[..len as usize]).unwrap_or("");
            self.derive_address(pp);
        }

        // ── PIN verification: cheap phase (write-ahead + in-memory check) ─
        // Slow KDF + AEAD decryption is deferred to `process_pending` so the
        // UI can render a "Verifying PIN…" indicator first.
        if let AppState::EnterPin { digits, len: 6, gate, .. } = self.state {
            self.begin_enter_pin(digits, gate, &touch_entropy, persist);
        }

        // ── PIN confirmation: cheap phase (digit comparison) ──────────────
        // Slow KDF + AEAD encryption is deferred to `process_pending`.
        if let AppState::ConfirmPin { pin, digits, len: 6, .. } = self.state {
            self.begin_confirm_pin(pin, digits);
        }

        // Sign the PSBT when user confirms on the review screen.
        // Pass the touch-event entropy as BIP340 aux_rand for fault-injection resistance.
        if matches!(prev, AppState::SignReview)
            && matches!(self.state, AppState::SignResult)
        {
            self.do_sign(&touch_entropy);
        }

        // Clear PSBT state when navigating back to Home.
        if matches!(self.state, AppState::Home) {
            self.psbt            = None;
            self.signed_psbt_b64_len = 0;
            self.scan_error_flag = false;
        }
    }

    // ── PIN orchestration: cheap (in handle_event) + slow (process_pending) ─

    /// Cheap phase of EnterPin resolution. Runs synchronously when the 6th
    /// digit is entered. Side-effects:
    ///   - Write-ahead increment of `failures` on disk (before any check).
    ///   - If the PIN is already known in-memory (in-session prompt), does the
    ///     plain comparison inline and transitions straight to the gate target
    ///     / EnterPin retry / PinLocked.
    ///   - Otherwise (cold-start: PIN must be verified via AEAD decryption),
    ///     parks the state machine in `PinVerifying` and returns. The actual
    ///     KDF + AEAD will run in `process_pending`.
    fn begin_enter_pin<F: FnMut(&[u8; PERSIST_BYTES])>(
        &mut self,
        digits:        [u8; 6],
        gate:          PinGate,
        touch_entropy: &[u8; 32],
        persist:       &mut F,
    ) {
        // Write-ahead: bump failures on disk *before* checking. A crash here
        // leaves the counter incremented, so restart cannot rewind the lockout.
        self.failures = self.failures.saturating_add(1);
        if let Some(ref mut img) = self.disk_image {
            update_lockout(img, self.failures, false);
            persist(img);
        }

        if let Some(stored) = self.pin {
            // In-session fast path: plain comparison, resolve immediately.
            let correct = ct_eq_pin(&stored, &digits);
            self.finalize_enter_pin(correct, gate, touch_entropy, persist);
        } else {
            // Cold-start path: AEAD verification is slow — park in PinVerifying
            // and let `process_pending` run the KDF after the UI redraws.
            self.state = AppState::PinVerifying { digits, gate };
        }
    }

    /// Resolves a PIN attempt outcome. Shared by the in-session fast path and
    /// the cold-start KDF path.
    fn finalize_enter_pin<F: FnMut(&[u8; PERSIST_BYTES])>(
        &mut self,
        correct:       bool,
        gate:          PinGate,
        touch_entropy: &[u8; 32],
        persist:       &mut F,
    ) {
        if correct {
            self.failures = 0;
            if let Some(ref mut img) = self.disk_image {
                update_lockout(img, 0, false);
                persist(img);
            }
            self.state = match gate {
                PinGate::Unlock       => AppState::Home,
                PinGate::ShowMnemonic => AppState::ShowMnemonic { page: 0 },
                PinGate::ChangePin    => AppState::SetPin {
                    order: shuffle(touch_entropy),
                    digits: [0u8; 6], len: 0,
                },
            };
        } else if self.failures >= PIN_MAX_ATTEMPTS {
            self.locked = true;
            if let Some(ref mut img) = self.disk_image {
                update_lockout(img, self.failures, true);
                persist(img);
            }
            self.state = AppState::PinLocked;
        } else {
            self.state = AppState::EnterPin {
                order:  shuffle(touch_entropy),
                digits: [0u8; 6], len: 0,
                gate,
            };
        }
    }

    /// Cheap phase of ConfirmPin resolution. Compares the entered digits to
    /// the originally chosen PIN. On mismatch → PinMismatch. On match → parks
    /// in `PinConfirming` for the slow encryption pass.
    fn begin_confirm_pin(&mut self, mut pin: [u8; 6], mut digits: [u8; 6]) {
        if !ct_eq_pin(&digits, &pin) {
            self.state = AppState::PinMismatch;
            zero_sensitive(&mut digits);
            zero_sensitive(&mut pin);
            return;
        }
        // digits is Copy — copied into PinConfirming; zero the local copy after.
        self.state = AppState::PinConfirming { new_pin: digits };
        zero_sensitive(&mut digits);
        zero_sensitive(&mut pin);
    }

    /// Runs the deferred slow work when the state machine is parked in
    /// `PinVerifying` or `PinConfirming`. The host (sim / firmware) calls this
    /// AFTER drawing the intermediate spinner screen, so the user sees
    /// "Verifying PIN…" / "Saving wallet…" during the PBKDF2 pass.
    ///
    /// `fresh_entropy` is consumed for shuffling the next PIN pad (verify path)
    /// and for generating fresh salt + nonce (confirm path).
    ///
    /// Returns `true` iff there was pending work to do.
    pub fn process_pending<F>(&mut self, fresh_entropy: [u8; 32], persist: &mut F) -> bool
    where
        F: FnMut(&[u8; PERSIST_BYTES]),
    {
        match self.state {
            AppState::PinVerifying { digits, gate } => {
                self.process_pin_verifying(digits, gate, &fresh_entropy, persist);
                true
            }
            AppState::PinConfirming { new_pin } => {
                self.process_pin_confirming(new_pin, &fresh_entropy, persist);
                true
            }
            _ => false,
        }
    }

    fn process_pin_verifying<F: FnMut(&[u8; PERSIST_BYTES])>(
        &mut self,
        mut digits:    [u8; 6],
        gate:          PinGate,
        fresh_entropy: &[u8; 32],
        persist:       &mut F,
    ) {
        // Cold-start: try to decrypt the disk image with the typed PIN.
        //
        // Security: `key` is derived from the typed PIN and must be zeroed on
        // the failure path so a wrong-PIN guess does not linger on the stack.
        // On success, `key` is moved into `self.enc_key` (no copy remains here).
        let correct = if let Some(ref img) = self.disk_image {
            let mut key = crypto::derive_key(&digits, &self.salt);
            match try_decrypt(img, &key) {
                Ok(secrets) => {
                    self.entropy = secrets.entropy;
                    self.seed    = secrets.seed;
                    self.address = taproot_address(&self.seed).unwrap_or([0u8; 62]);
                    self.words   = generate_words(&self.entropy);
                    self.pin     = Some(digits);
                    self.enc_key = Some(key);
                    // `key` was moved into `self.enc_key` — no copy remains here.
                    true
                }
                Err(_) => {
                    // Wrong PIN: zero the derived key so it does not linger on
                    // the stack after this scope exits.
                    zero_sensitive(&mut key);
                    false
                }
            }
        } else {
            false
        };

        // digits was Copy'd into self.pin on success; zero the local parameter copy.
        zero_sensitive(&mut digits);

        self.finalize_enter_pin(correct, gate, fresh_entropy, persist);
    }

    fn process_pin_confirming<F: FnMut(&[u8; PERSIST_BYTES])>(
        &mut self,
        mut new_pin:   [u8; 6],
        fresh_entropy: &[u8; 32],
        persist:       &mut F,
    ) {
        let mut salt  = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        salt.copy_from_slice(&fresh_entropy[..SALT_LEN]);
        nonce.copy_from_slice(&fresh_entropy[SALT_LEN..SALT_LEN + NONCE_LEN]);

        // `key` is `[u8; KEY_LEN]` (Copy). It is zeroed on both branches so the
        // PBKDF2-derived bytes don't linger on the stack if encryption fails.
        let mut key = crypto::derive_key(&new_pin, &salt);
        let secrets = Secrets { entropy: self.entropy, seed: self.seed };
        match encrypt_into_blob(&secrets, &salt, &nonce, &key, 0, false) {
            Ok(image) => {
                self.salt       = salt;
                self.enc_key    = Some(key); // key is Copy — local still alive
                zero_sensitive(&mut key);    // zero the local copy
                self.pin        = Some(new_pin);
                self.failures   = 0;
                self.locked     = false;
                self.disk_image = Some(image);
                persist(self.disk_image.as_ref().unwrap());
                self.state = AppState::Home;
            }
            Err(_) => {
                zero_sensitive(&mut key); // zero key — wrong-PIN derived bytes must not linger
                self.state = AppState::PinMismatch;
            }
        }

        // new_pin was Copy'd into self.pin on success; zero the local parameter copy.
        zero_sensitive(&mut new_pin);
    }

    /// True iff the state machine is parked in a deferred-work state and the
    /// caller should redraw, then call `process_pending`.
    pub fn has_pending_work(&self) -> bool {
        matches!(self.state, AppState::PinVerifying { .. } | AppState::PinConfirming { .. })
    }

    fn derive_address(&mut self, passphrase: &str) {
        if let Ok(m) = Mnemonic::from_entropy(&self.entropy) {
            let mut seed = m.to_seed_normalized(passphrase);
            debug_assert!(taproot_address(&seed).is_some(), "taproot derivation failed");
            if let Some(addr) = taproot_address(&seed) {
                self.address = addr;
                self.seed    = seed; // seed is Copy — self.seed now holds it
            }
            // Zero the local copy regardless of derivation success.
            for b in seed.iter_mut() { unsafe { core::ptr::write_volatile(b, 0); } }
        }
    }

    /// Decodes a Base64 PSBT, parses it, and transitions to SignReview on success.
    /// On decode or parse failure stays in SignScan and sets `scan_error_flag = true`
    /// so the draw layer can show a "PSBT rejected — rescan" hint.
    fn load_psbt(&mut self, b64: &[u8]) {
        let mut raw = [0u8; MAX_PSBT_RAW];
        let Some(raw_len) = base64::decode(b64, &mut raw) else {
            self.scan_error_flag = true;
            return;
        };
        match ParsedPsbt::parse(&raw[..raw_len]) {
            Ok(parsed) => {
                self.scan_error_flag = false;
                self.psbt            = Some(parsed);
                self.state           = AppState::SignReview;
            }
            Err(_) => {
                self.scan_error_flag = true;
            }
        }
    }

    /// Signs the stored PSBT with our BIP86 key and Base64-encodes the result.
    fn do_sign(&mut self, aux_rand: &[u8; 32]) {
        let Some(ref mut psbt) = self.psbt else { return };
        if sign_psbt(psbt, &self.seed, aux_rand).is_err() { return }

        // Serialise the unsigned tx (needed as the global map entry in the signed PSBT).
        let mut tx_buf  = [0u8; MAX_PSBT_RAW];
        let Some(tx_len) = psbt::serialize_unsigned_tx(psbt, &mut tx_buf) else { return };

        // Build the signed PSBT binary.
        let mut psbt_bin = [0u8; MAX_PSBT_RAW];
        let Ok(psbt_len) = psbt::encode_signed(psbt, &tx_buf[..tx_len], &mut psbt_bin) else { return };

        // Base64-encode for QR display.
        if psbt_len.div_ceil(3) * 4 > self.signed_psbt_b64.len() {
            // Signed PSBT would overflow our base64 buffer — drop it rather than panic.
            return;
        }
        let b64_len = base64::encode(&psbt_bin[..psbt_len], &mut self.signed_psbt_b64);
        self.signed_psbt_b64_len = b64_len;
    }
}

impl Drop for ColdWallet {
    fn drop(&mut self) {
        zero_sensitive(&mut self.entropy);
        zero_sensitive(&mut self.seed);
        if let Some(ref mut p) = self.pin {
            zero_sensitive(p);
        }
        if let Some(ref mut k) = self.enc_key {
            zero_sensitive(k);
        }
        zero_sensitive(&mut self.address);
        zero_sensitive(&mut self.signed_psbt_b64);
        zero_sensitive(&mut self.salt);

        // Clear the mnemonic word pointers. `words` is `[&'static str; 24]`
        // where each element points into the BIP39 static word-list. The
        // *sequence of pointers* encodes the mnemonic: an attacker who reads
        // freed memory can reconstruct the 24-word phrase from the pointer
        // values alone, without needing the underlying string data. Overwrite
        // every slot with a pointer to the empty string so the original
        // sequence is no longer recoverable from this struct.
        for slot in self.words.iter_mut() {
            // SAFETY: volatile write prevents the compiler from treating these
            // as dead stores and eliding them at optimisation time.
            unsafe {
                core::ptr::write_volatile(slot as *mut &'static str, "");
            }
        }
    }
}

impl Default for ColdWallet {
    fn default() -> Self { Self::new() }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Overwrites every byte with 0 via volatile writes to prevent dead-store elimination.
fn zero_sensitive<const N: usize>(buf: &mut [u8; N]) {
    for b in buf.iter_mut() {
        // SAFETY: volatile write prevents the compiler from eliding this zeroing.
        unsafe { core::ptr::write_volatile(b, 0); }
    }
}

/// Compares two PIN arrays without early exit to avoid timing side channels.
fn ct_eq_pin(a: &[u8; 6], b: &[u8; 6]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..6 { diff |= a[i] ^ b[i]; }
    diff == 0
}

// (new_state, pin_to_store, words_to_store, entropy_to_store)
type StepResult = (AppState, Option<[u8; 6]>, Option<[&'static str; 24]>, Option<[u8; 32]>);

fn no_change(state: AppState) -> StepResult {
    (state, None, None, None)
}

// ── State machine dispatch ────────────────────────────────────────────────────

fn step(state: AppState, event: WalletEvent, stored_pin: Option<[u8; 6]>) -> StepResult {
    // PsbtScanned is handled before step() is called (early return in handle_event).
    let WalletEvent::Touch { x, y, entropy } = event else { return no_change(state) };

    match state {
        AppState::Welcome =>
            step_welcome(x, y, &entropy),
        AppState::NewWallet { page } =>
            step_new_wallet(x, y, page),
        AppState::EnterPassphrase { buf, len } =>
            step_enter_passphrase(x, y, &entropy, buf, len),
        AppState::SetPin { order, digits, len } =>
            step_set_pin(x, y, &entropy, order, digits, len),
        AppState::ConfirmPin { pin, order, digits, len } =>
            step_confirm_pin(x, y, pin, order, digits, len),
        AppState::PinMismatch =>
            step_pin_mismatch(&entropy),
        AppState::EnterPin { order, digits, len, gate } =>
            step_enter_pin(x, y, order, digits, len, gate, stored_pin),
        AppState::Home =>
            step_home(x, y),
        AppState::Receive =>
            step_receive(x, y),
        AppState::Accounts =>
            step_accounts(x, y),
        AppState::Settings =>
            step_settings(x, y, &entropy),
        AppState::ShowMnemonic { page } =>
            step_show_mnemonic(x, y, page),
        AppState::About =>
            step_about(x, y),
        AppState::SignScan =>
            step_sign_scan(x, y),
        AppState::SignReview =>
            step_sign_review(x, y),
        AppState::SignResult =>
            step_sign_result(x, y),
        AppState::RestoreWallet { word_idx, buf, buf_len, confirmed, error } =>
            step_restore_wallet(x, y, word_idx, buf, buf_len, confirmed, error),
        // Terminal / deferred-work states ignore input.
        AppState::PinLocked
        | AppState::PinVerifying { .. }
        | AppState::PinConfirming { .. } =>
            no_change(state),
    }
}

// ── Per-state handlers ────────────────────────────────────────────────────────

fn step_welcome(x: i32, y: i32, entropy: &[u8; 32]) -> StepResult {
    if in_rect(x, y, BTN_X, BTN_NEW_Y, BTN_W, BTN_H) {
        // Store entropy so derive_address() can reconstruct the mnemonic later.
        (AppState::NewWallet { page: 0 }, None, Some(generate_words(entropy)), Some(*entropy))
    } else if in_rect(x, y, BTN_X, BTN_RESTORE_Y, BTN_W, BTN_H) {
        (AppState::RestoreWallet {
            word_idx: 0, buf: [0u8; 8], buf_len: 0, confirmed: [0u16; 24], error: false,
        }, None, None, None)
    } else {
        (AppState::Welcome, None, None, None)
    }
}

fn step_new_wallet(x: i32, y: i32, page: u8) -> StepResult {
    let is_prev = in_rect(x, y, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H);
    let is_next = in_rect(x, y, NAV_NEXT_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H);

    if is_next && page < 3 {
        (AppState::NewWallet { page: page + 1 }, None, None, None)
    } else if is_next && page == 3 {
        (AppState::EnterPassphrase { buf: [0u8; 32], len: 0 }, None, None, None)
    } else if is_prev && page > 0 {
        (AppState::NewWallet { page: page - 1 }, None, None, None)
    } else {
        (AppState::NewWallet { page }, None, None, None)
    }
}

fn step_enter_passphrase(x: i32, y: i32, entropy: &[u8; 32], buf: [u8; 32], len: u8) -> StepResult {
    let next = match passphrase_key_at(x, y) {
        Some(KeyPress::Char(c)) if len < 32 => {
            let mut b = buf; b[len as usize] = c;
            Some(AppState::EnterPassphrase { buf: b, len: len + 1 })
        }
        Some(KeyPress::Space) if len < 32 => {
            let mut b = buf; b[len as usize] = b' ';
            Some(AppState::EnterPassphrase { buf: b, len: len + 1 })
        }
        Some(KeyPress::Backspace) if len > 0 =>
            Some(AppState::EnterPassphrase { buf, len: len - 1 }),
        Some(KeyPress::Confirm) if len > 0 =>
            Some(AppState::SetPin { order: shuffle(entropy), digits: [0u8; 6], len: 0 }),
        Some(KeyPress::Skip) =>
            Some(AppState::SetPin { order: shuffle(entropy), digits: [0u8; 6], len: 0 }),
        _ => None,
    };
    (next.unwrap_or(AppState::EnterPassphrase { buf, len }), None, None, None)
}

fn step_set_pin(x: i32, y: i32, entropy: &[u8; 32], order: [u8; 10], mut digits: [u8; 6], len: u8) -> StepResult {
    if let Some(digit) = pin_digit_at(x, y, &order) {
        if len < 6 {
            digits[len as usize] = digit;
            let new_len = len + 1;
            if new_len == 6 {
                (AppState::ConfirmPin { pin: digits, order: shuffle(entropy), digits: [0u8; 6], len: 0 }, None, None, None)
            } else {
                (AppState::SetPin { order, digits, len: new_len }, None, None, None)
            }
        } else {
            (AppState::SetPin { order, digits, len }, None, None, None)
        }
    } else if in_rect(x, y, PIN_DEL_X, PIN_DEL_Y, PIN_DEL_W, PIN_DEL_H) && len > 0 {
        (AppState::SetPin { order, digits, len: len - 1 }, None, None, None)
    } else {
        (AppState::SetPin { order, digits, len }, None, None, None)
    }
}

/// Builds digits one tap at a time. The cheap phase (`begin_confirm_pin`) runs
/// in `handle_event` once `len == 6`; the slow encryption pass runs later in
/// `process_pin_confirming` via `process_pending`.
fn step_confirm_pin(x: i32, y: i32, pin: [u8; 6], order: [u8; 10], mut digits: [u8; 6], len: u8) -> StepResult {
    if let Some(digit) = pin_digit_at(x, y, &order) {
        if len < 6 {
            digits[len as usize] = digit;
            (AppState::ConfirmPin { pin, order, digits, len: len + 1 }, None, None, None)
        } else {
            (AppState::ConfirmPin { pin, order, digits, len }, None, None, None)
        }
    } else if in_rect(x, y, PIN_DEL_X, PIN_DEL_Y, PIN_DEL_W, PIN_DEL_H) && len > 0 {
        (AppState::ConfirmPin { pin, order, digits, len: len - 1 }, None, None, None)
    } else {
        (AppState::ConfirmPin { pin, order, digits, len }, None, None, None)
    }
}

fn step_pin_mismatch(entropy: &[u8; 32]) -> StepResult {
    (AppState::SetPin { order: shuffle(entropy), digits: [0u8; 6], len: 0 }, None, None, None)
}

/// Builds digits one tap at a time. The cheap phase (`begin_enter_pin`) runs
/// in `handle_event` once `len == 6`; cold-start AEAD verification runs later
/// in `process_pin_verifying` via `process_pending`.
fn step_enter_pin(
    x: i32, y: i32,
    order: [u8; 10], mut digits: [u8; 6], len: u8,
    gate: PinGate,
    _stored_pin: Option<[u8; 6]>,
) -> StepResult {
    if let Some(digit) = pin_digit_at(x, y, &order) {
        if len < 6 {
            digits[len as usize] = digit;
            (AppState::EnterPin { order, digits, len: len + 1, gate }, None, None, None)
        } else {
            (AppState::EnterPin { order, digits, len, gate }, None, None, None)
        }
    } else if in_rect(x, y, PIN_DEL_X, PIN_DEL_Y, PIN_DEL_W, PIN_DEL_H) && len > 0 {
        (AppState::EnterPin { order, digits, len: len - 1, gate }, None, None, None)
    } else {
        (AppState::EnterPin { order, digits, len, gate }, None, None, None)
    }
}

fn step_home(x: i32, y: i32) -> StepResult {
    if in_rect(x, y, HOME_X0, HOME_Y0, HOME_BTN_W, HOME_BTN_H) {
        (AppState::Receive, None, None, None)
    } else if in_rect(x, y, HOME_X1, HOME_Y0, HOME_BTN_W, HOME_BTN_H) {
        (AppState::SignScan, None, None, None)
    } else if in_rect(x, y, HOME_X0, HOME_Y1, HOME_BTN_W, HOME_BTN_H) {
        (AppState::Accounts, None, None, None)
    } else if in_rect(x, y, HOME_X1, HOME_Y1, HOME_BTN_W, HOME_BTN_H) {
        (AppState::Settings, None, None, None)
    } else {
        (AppState::Home, None, None, None)
    }
}

fn step_receive(x: i32, y: i32) -> StepResult {
    if in_rect(x, y, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H) {
        (AppState::Home, None, None, None)
    } else {
        (AppState::Receive, None, None, None)
    }
}

fn step_accounts(x: i32, y: i32) -> StepResult {
    if in_rect(x, y, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H) {
        (AppState::Home, None, None, None)
    } else {
        (AppState::Accounts, None, None, None)
    }
}

fn step_settings(x: i32, y: i32, entropy: &[u8; 32]) -> StepResult {
    if in_rect(x, y, SETTINGS_BTN_X, SETTINGS_Y0, SETTINGS_BTN_W, SETTINGS_BTN_H) {
        (AppState::EnterPin {
            order: shuffle(entropy), digits: [0u8; 6], len: 0,
            gate: PinGate::ShowMnemonic,
        }, None, None, None)
    } else if in_rect(x, y, SETTINGS_BTN_X, SETTINGS_Y1, SETTINGS_BTN_W, SETTINGS_BTN_H) {
        (AppState::EnterPin {
            order: shuffle(entropy), digits: [0u8; 6], len: 0,
            gate: PinGate::ChangePin,
        }, None, None, None)
    } else if in_rect(x, y, SETTINGS_BTN_X, SETTINGS_Y2, SETTINGS_BTN_W, SETTINGS_BTN_H) {
        (AppState::About, None, None, None)
    } else if in_rect(x, y, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H) {
        (AppState::Home, None, None, None)
    } else {
        (AppState::Settings, None, None, None)
    }
}

fn step_show_mnemonic(x: i32, y: i32, page: u8) -> StepResult {
    let is_prev = in_rect(x, y, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H);
    let is_next = in_rect(x, y, NAV_NEXT_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H);

    if is_next && page < 3 {
        (AppState::ShowMnemonic { page: page + 1 }, None, None, None)
    } else if is_next && page == 3 {
        (AppState::Settings, None, None, None)
    } else if is_prev && page > 0 {
        (AppState::ShowMnemonic { page: page - 1 }, None, None, None)
    } else if is_prev {
        (AppState::Settings, None, None, None)
    } else {
        (AppState::ShowMnemonic { page }, None, None, None)
    }
}

fn step_about(x: i32, y: i32) -> StepResult {
    if in_rect(x, y, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H) {
        (AppState::Settings, None, None, None)
    } else {
        (AppState::About, None, None, None)
    }
}

fn step_sign_scan(x: i32, y: i32) -> StepResult {
    if in_rect(x, y, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H) {
        (AppState::Home, None, None, None)
    } else {
        (AppState::SignScan, None, None, None)
    }
}

fn step_sign_review(x: i32, y: i32) -> StepResult {
    if in_rect(x, y, NAV_NEXT_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H) {
        (AppState::SignResult, None, None, None)
    } else if in_rect(x, y, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H) {
        (AppState::Home, None, None, None)
    } else {
        (AppState::SignReview, None, None, None)
    }
}

fn step_sign_result(x: i32, y: i32) -> StepResult {
    if in_rect(x, y, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H) {
        (AppState::Home, None, None, None)
    } else {
        (AppState::SignResult, None, None, None)
    }
}

fn step_restore_wallet(
    x: i32, y: i32,
    word_idx: u8, buf: [u8; 8], buf_len: u8,
    confirmed: [u16; 24], error: bool,
) -> StepResult {
    // Cancel → Welcome
    if matches!(passphrase_key_at(x, y), Some(KeyPress::Skip)) {
        return (AppState::Welcome, None, None, None);
    }

    // Suggestion buttons tap
    let suggestions = find_matches(&buf, buf_len);
    if let Some(word_index) = tapped_suggestion(x, y, suggestions) {
        debug_assert!((word_idx as usize) < confirmed.len());
        let mut c = confirmed;
        c[word_idx as usize] = word_index;
        let next = word_idx + 1;
        if next == 24 {
            // All words entered — validate checksum
            if let Some(ent) = indices_to_entropy(&c) {
                let words = generate_words(&ent);
                return (
                    AppState::EnterPassphrase { buf: [0u8; 32], len: 0 },
                    None,
                    Some(words),
                    Some(ent),
                );
            }
            // Bad checksum — stay at word 0 with visible error
            return (AppState::RestoreWallet {
                word_idx: 0, buf: [0u8; 8], buf_len: 0,
                confirmed: [0u16; 24], error: true,
            }, None, None, None);
        }
        return (AppState::RestoreWallet {
            word_idx: next, buf: [0u8; 8], buf_len: 0, confirmed: c, error: false,
        }, None, None, None);
    }

    // Keyboard input — clears error on any keystroke
    match passphrase_key_at(x, y) {
        Some(KeyPress::Char(c)) if buf_len < 8 => {
            let mut b = buf;
            b[buf_len as usize] = c | 0x20; // uppercase → lowercase
            (AppState::RestoreWallet { word_idx, buf: b, buf_len: buf_len + 1, confirmed, error: false }, None, None, None)
        }
        Some(KeyPress::Backspace) if buf_len > 0 => {
            (AppState::RestoreWallet { word_idx, buf, buf_len: buf_len - 1, confirmed, error: false }, None, None, None)
        }
        _ => (AppState::RestoreWallet { word_idx, buf, buf_len, confirmed, error }, None, None, None),
    }
}

// ── BIP39 helpers ─────────────────────────────────────────────────────────────

/// Returns up to 3 BIP39 word indices that start with the given prefix.
/// Returns all-None if fewer than 1 character has been typed.
pub(crate) fn find_matches(buf: &[u8; 8], buf_len: u8) -> [Option<u16>; 3] {
    if buf_len == 0 {
        return [None; 3];
    }
    let prefix = core::str::from_utf8(&buf[..buf_len as usize]).unwrap_or("");
    let word_list = bip39::Language::English.word_list();
    let mut out = [None; 3];
    let mut count = 0usize;
    for (i, &word) in word_list.iter().enumerate() {
        if word.starts_with(prefix) {
            out[count] = Some(i as u16);
            count += 1;
            if count == 3 { break; }
        }
    }
    out
}

fn tapped_suggestion(x: i32, y: i32, matches: [Option<u16>; 3]) -> Option<u16> {
    let xs = [RESTORE_SUGGEST_X0, RESTORE_SUGGEST_X1, RESTORE_SUGGEST_X2];
    for (i, &sx) in xs.iter().enumerate() {
        if in_rect(x, y, sx, RESTORE_SUGGEST_Y, RESTORE_SUGGEST_W, RESTORE_SUGGEST_H) {
            return matches[i];
        }
    }
    None
}

fn generate_words(entropy: &[u8; 32]) -> [&'static str; 24] {
    let mut words = [""; 24];
    if let Ok(m) = Mnemonic::from_entropy(entropy) {
        for (i, w) in m.words().enumerate() {
            if i >= 24 { break; }
            words[i] = w;
        }
    }
    words
}

// ── PIN helpers ───────────────────────────────────────────────────────────────

/// Fisher-Yates shuffle of the digits 0–9 for the anti-smudge PIN pad.
///
/// Folds all 256 bits of platform entropy into a 64-bit seed, then drives a
/// splitmix64 PRNG for the swaps — far stronger than the previous 32-bit LCG
/// seed (whose state could not even cover the 10! possible pads). On hardware,
/// `entropy` must come from the TRNG; on the simulator it is `getrandom`.
pub fn shuffle(entropy: &[u8; 32]) -> [u8; 10] {
    let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
    for chunk in entropy.chunks_exact(8) {
        let mut b = [0u8; 8];
        b.copy_from_slice(chunk);
        s ^= u64::from_le_bytes(b);
        s = s.rotate_left(17);
    }
    let mut next = || {
        s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };

    let mut arr = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    for i in (1..10usize).rev() {
        // Bias is ~10/2⁶⁴ for a 64-bit draw over a range ≤ 10 — negligible.
        let j = (next() % (i as u64 + 1)) as usize;
        arr.swap(i, j);
    }
    arr
}

pub fn pin_digit_at(x: i32, y: i32, order: &[u8; 10]) -> Option<u8> {
    for (pos, &digit) in order.iter().enumerate() {
        let (kx, ky) = pin_key_pos(pos);
        if in_rect(x, y, kx, ky, PIN_KEY_W, PIN_KEY_H) {
            return Some(digit);
        }
    }
    None
}

pub fn pin_key_pos(pos: usize) -> (i32, i32) {
    let col = (pos % 5) as i32;
    let row = (pos / 5) as i32;
    let kx  = PIN_ROW_X + col * PIN_KEY_STEP;
    let ky  = if row == 0 { PIN_ROW0_Y } else { PIN_ROW1_Y };
    (kx, ky)
}

pub fn in_rect(x: i32, y: i32, rx: i32, ry: i32, rw: i32, rh: i32) -> bool {
    x >= rx && x < rx + rw && y >= ry && y < ry + rh
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // LCG constants used to expand a seed into deterministic test entropy.
    const LCG_MULTIPLIER: u32 = 1_664_525;
    const LCG_INCREMENT: u32 = 1_013_904_223;
    const ORDER: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    /// Drive `wallet.handle_event` with a touch at (x,y), seeded entropy, no-op persist.
    fn touch(wallet: &mut ColdWallet, x: i32, y: i32, seed: u32) {
        let (event, entropy) = create_touch_event_with_entropy(x, y, seed);
        wallet.handle_event(event, &mut |_: &_| {});
        if wallet.has_pending_work() {
            wallet.process_pending(entropy, &mut |_: &_| {});
        }
    }

    /// Creates a touch event with reproducible entropy derived from a seed.
    fn create_touch_event_with_entropy(x: i32, y: i32, seed: u32) -> (WalletEvent, [u8; 32]) {
        let mut entropy = [0u8; 32];
        let mut s = seed;
        for chunk in entropy.chunks_exact_mut(4) {
            s = s.wrapping_mul(LCG_MULTIPLIER).wrapping_add(LCG_INCREMENT);
            chunk.copy_from_slice(&s.to_le_bytes());
        }
        (WalletEvent::Touch { x, y, entropy }, entropy)
    }

    #[test]
    fn find_matches_filters_by_prefix() {
        let buf: [u8; 8] = *b"ab\0\0\0\0\0\0";
        let matches = find_matches(&buf, 2);
        let word_list = bip39::Language::English.word_list();
        for m in matches {
            let word = word_list[m.unwrap() as usize];
            assert!(word.starts_with("ab"), "expected 'ab' prefix, got: {word}");
        }
    }

    #[test]
    fn find_matches_empty_prefix_returns_none() {
        let buf = [0u8; 8];
        let matches = find_matches(&buf, 0);
        assert_eq!(matches, [None; 3]);
    }

    #[test]
    fn restore_wallet_keyboard_entry() {
        let init = AppState::RestoreWallet {
            word_idx: 0, buf: [0u8; 8], buf_len: 0, confirmed: [0u16; 24], error: false,
        };
        let (event, _) = create_touch_event_with_entropy(ROW0_X + 1, ROW0_Y + 1, 77);
        let (state, _, _, _) = step(init, event, None);
        match state {
            AppState::RestoreWallet { buf, buf_len, .. } => {
                assert_eq!(buf_len, 1);
                assert_eq!(buf[0], b'q');
            }
            _ => panic!("expected RestoreWallet"),
        }
    }

    #[test]
    fn restore_wallet_backspace() {
        let mut buf = [0u8; 8]; buf[0] = b'a';
        let init = AppState::RestoreWallet {
            word_idx: 0, buf, buf_len: 1, confirmed: [0u16; 24], error: false,
        };
        let (event, _) = create_touch_event_with_entropy(BKSP_X + BKSP_W - 5, ROW2_Y + 1, 88);
        let (state, _, _, _) = step(init, event, None);
        match state {
            AppState::RestoreWallet { buf_len, .. } => assert_eq!(buf_len, 0),
            _ => panic!("expected RestoreWallet"),
        }
    }

    #[test]
    fn restore_wallet_cancel_returns_to_welcome() {
        let init = AppState::RestoreWallet {
            word_idx: 5, buf: [0u8; 8], buf_len: 0, confirmed: [0u16; 24], error: false,
        };
        let (event, _) = create_touch_event_with_entropy(PP_SKIP_X + 1, PP_BTN_Y + 1, 99);
        let (state, _, _, _) = step(init, event, None);
        assert_eq!(state, AppState::Welcome);
    }

    #[test]
    fn in_rect_bounds() {
        assert!(in_rect(0, 0, 0, 0, 1, 1));
        assert!(!in_rect(1, 0, 0, 0, 1, 1));
        assert!(!in_rect(0, 1, 0, 0, 1, 1));
    }

    #[test]
    fn shuffle_is_permutation() {
        let mut ent = [0u8; 32];
        for (i, b) in ent.iter_mut().enumerate() { *b = (i as u8).wrapping_mul(37).wrapping_add(5); }
        let order = shuffle(&ent);
        let mut seen = [false; 10];
        for &d in &order {
            assert!(d < 10);
            assert!(!seen[d as usize]);
            seen[d as usize] = true;
        }
    }

    #[test]
    fn pin_key_position_grid() {
        assert_eq!(pin_key_pos(0), (PIN_ROW_X, PIN_ROW0_Y));
        assert_eq!(pin_key_pos(4), (PIN_ROW_X + 4 * PIN_KEY_STEP, PIN_ROW0_Y));
        assert_eq!(pin_key_pos(5), (PIN_ROW_X, PIN_ROW1_Y));
        assert_eq!(pin_key_pos(9), (PIN_ROW_X + 4 * PIN_KEY_STEP, PIN_ROW1_Y));
    }

    #[test]
    fn pin_digit_lookup() {
        let order = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0];
        let (x, y) = pin_key_pos(2);
        assert_eq!(pin_digit_at(x + 1, y + 1, &order), Some(7));
        assert_eq!(pin_digit_at(0, 0, &order), None);
    }

    #[test]
    fn step_welcome_new_wallet_generates_words() {
        let (event, event_entropy) = create_touch_event_with_entropy(BTN_X + 1, BTN_NEW_Y + 1, 42);
        let (state, pin, words, returned_entropy) = step(AppState::Welcome, event, None);
        assert_eq!(state, AppState::NewWallet { page: 0 });
        assert!(pin.is_none());
        let returned_entropy = returned_entropy.expect("entropy should be returned");
        assert_eq!(returned_entropy, event_entropy);
        let words = words.expect("words should be generated");
        assert_eq!(words, generate_words(&returned_entropy));
        let word_list = bip39::Language::English.word_list();
        for word in &words {
            assert!(word_list.contains(word));
        }
    }

    // ── PIN UI tests (no encryption needed — disk_image stays None) ──────

    /// Builds digits without going through encryption: handle_event will land in
    /// EnterPin{len:6}, begin_enter_pin runs and, because self.pin is set and
    /// disk_image is None, finalize_enter_pin is called inline (no parking).
    fn build_wallet_with_pin(pin: [u8; 6]) -> ColdWallet {
        let mut w = ColdWallet::new();
        w.pin = Some(pin);
        w
    }

    #[test]
    fn enter_pin_unlock_with_in_memory_pin() {
        let stored = [0u8, 1, 2, 3, 4, 5];
        let mut w  = build_wallet_with_pin(stored);
        w.state = AppState::EnterPin { order: ORDER, digits: [0u8; 6], len: 0, gate: PinGate::Unlock };
        for pos in 0..6 {
            let (x, y) = pin_key_pos(pos);
            touch(&mut w, x + 1, y + 1, 5);
        }
        assert_eq!(w.state, AppState::Home);
        assert_eq!(w.failures, 0);
    }

    #[test]
    fn enter_pin_show_mnemonic_gate() {
        let stored = [0u8, 1, 2, 3, 4, 5];
        let mut w  = build_wallet_with_pin(stored);
        w.state = AppState::EnterPin { order: ORDER, digits: [0u8; 6], len: 0, gate: PinGate::ShowMnemonic };
        for pos in 0..6 {
            let (x, y) = pin_key_pos(pos);
            touch(&mut w, x + 1, y + 1, 12);
        }
        assert_eq!(w.state, AppState::ShowMnemonic { page: 0 });
    }

    #[test]
    fn enter_pin_change_pin_gate() {
        let stored = [0u8, 1, 2, 3, 4, 5];
        let mut w  = build_wallet_with_pin(stored);
        w.state = AppState::EnterPin { order: ORDER, digits: [0u8; 6], len: 0, gate: PinGate::ChangePin };
        for pos in 0..6 {
            let (x, y) = pin_key_pos(pos);
            touch(&mut w, x + 1, y + 1, 13);
        }
        assert!(matches!(w.state, AppState::SetPin { .. }));
    }

    #[test]
    fn enter_pin_wrong_increments_failures() {
        let stored = [0u8, 1, 2, 3, 4, 5];
        let mut w  = build_wallet_with_pin(stored);
        w.state = AppState::EnterPin { order: ORDER, digits: [0u8; 6], len: 0, gate: PinGate::Unlock };
        for pos in [1usize, 2, 3, 4, 5, 6] {
            let (x, y) = pin_key_pos(pos);
            touch(&mut w, x + 1, y + 1, 6);
        }
        assert!(matches!(w.state, AppState::EnterPin { .. }));
        assert_eq!(w.failures, 1);
    }

    #[test]
    fn enter_pin_lockout_after_max_attempts() {
        let stored = [0u8, 1, 2, 3, 4, 5];
        let mut w  = build_wallet_with_pin(stored);
        w.state = AppState::EnterPin { order: ORDER, digits: [0u8; 6], len: 0, gate: PinGate::Unlock };

        for _ in 0..PIN_MAX_ATTEMPTS {
            for &pos in &[1usize, 2, 3, 4, 5, 6] {
                let (x, y) = pin_key_pos(pos);
                touch(&mut w, x + 1, y + 1, 6);
            }
        }
        assert_eq!(w.state, AppState::PinLocked);
        assert!(w.locked);
        assert_eq!(w.failures, PIN_MAX_ATTEMPTS);
    }

    // ── Write-ahead persistence: failures must be persisted BEFORE check ──

    #[test]
    fn write_ahead_persist_runs_before_check() {
        use core::cell::Cell;

        // Build a wallet with a known disk_image so persist callbacks fire.
        let mut w = ColdWallet::new();
        w.entropy[0] = 1; w.seed[0] = 1;
        let secrets = Secrets { entropy: w.entropy, seed: w.seed };
        let salt  = [0xaau8; SALT_LEN];
        let nonce = [0xbbu8; NONCE_LEN];
        let key   = [0xccu8; KEY_LEN];
        let image = encrypt_into_blob(&secrets, &salt, &nonce, &key, 0, false).unwrap();
        w.salt       = salt;
        w.enc_key    = Some(key);
        w.pin        = Some([0u8, 1, 2, 3, 4, 5]);
        w.disk_image = Some(image);
        w.state = AppState::EnterPin { order: ORDER, digits: [0u8; 6], len: 0, gate: PinGate::Unlock };

        // Persist callback records the failures field of every write it sees.
        let writes: Cell<u8> = Cell::new(0);
        let last_failures: Cell<u8> = Cell::new(255);
        let mut persist = |blob: &[u8; PERSIST_BYTES]| {
            writes.set(writes.get() + 1);
            last_failures.set(blob[1]);
        };

        // Wrong PIN (positions 1..7 give digits [1,2,3,4,5,6]).
        for &pos in &[1usize, 2, 3, 4, 5, 6] {
            let (x, y) = pin_key_pos(pos);
            let (event, _) = create_touch_event_with_entropy(x + 1, y + 1, 7);
            w.handle_event(event, &mut persist);
        }

        // At least one persist call must have written failures>=1 (the
        // write-ahead) before the comparison resolved. This proves the counter
        // hit disk before the check could short-circuit it.
        assert!(writes.get() >= 1, "persist was never called");
        assert!(last_failures.get() >= 1, "persisted failures field was never bumped");
        assert_eq!(w.failures, 1);
    }

    // ── ConfirmPin → encryption ───────────────────────────────────────────

    // ── End-to-end: setup → restart → AEAD-unlock ─────────────────────────

    /// Drives ConfirmPin to completion, returning the persisted disk image.
    fn setup_wallet_and_capture_image(pin: [u8; 6]) -> (ColdWallet, [u8; PERSIST_BYTES]) {
        let mut w = ColdWallet::new();
        w.entropy[0] = 0x42;
        w.seed[0]    = 0x42;
        w.state = AppState::ConfirmPin { pin, order: ORDER, digits: [0u8; 6], len: 0 };

        let mut captured: Option<[u8; PERSIST_BYTES]> = None;
        let mut persist = |blob: &[u8; PERSIST_BYTES]| { captured = Some(*blob); };
        for &digit in &pin {
            let pos = digit as usize; // ORDER is identity, so pos == digit
            let (x, y) = pin_key_pos(pos);
            let (event, entropy) = create_touch_event_with_entropy(x + 1, y + 1, 7);
            w.handle_event(event, &mut persist);
            if w.has_pending_work() {
                w.process_pending(entropy, &mut persist);
            }
        }
        let image = captured.expect("persist must have been called");
        (w, image)
    }

    /// Type the given PIN by looking up each digit's current position in the
    /// shuffled pad — the pad re-shuffles after every wrong attempt.
    fn type_pin_into(w: &mut ColdWallet, pin: [u8; 6]) {
        for &digit in &pin {
            let order = match w.state {
                AppState::EnterPin   { order, .. } => order,
                AppState::ConfirmPin { order, .. } => order,
                AppState::SetPin     { order, .. } => order,
                _ => panic!("type_pin_into called from non-PIN state {:?}", w.state),
            };
            let pos = order.iter().position(|&d| d == digit).unwrap();
            let (x, y) = pin_key_pos(pos);
            touch(w, x + 1, y + 1, 11);
        }
    }

    #[test]
    fn setup_then_restart_unlocks_with_aead() {
        let pin = [0u8, 1, 2, 3, 4, 5];
        let (orig, image) = setup_wallet_and_capture_image(pin);

        // Simulate restart.
        let mut w = ColdWallet::from_disk_image(image, [0xa5u8; 32]).unwrap();
        assert!(matches!(w.state, AppState::EnterPin { gate: PinGate::Unlock, .. }));
        assert_eq!(w.failures, 0);
        assert!(!w.locked);
        assert!(w.pin.is_none(), "cold start must not carry in-memory PIN");

        type_pin_into(&mut w, pin);
        assert_eq!(w.state, AppState::Home);
        // Seed was recovered from ciphertext.
        assert_eq!(w.seed[0], orig.seed[0]);
        assert_eq!(w.entropy[0], orig.entropy[0]);
        assert_eq!(w.failures, 0);
    }

    #[test]
    fn setup_then_restart_wrong_pin_increments_and_persists() {
        let correct = [0u8, 1, 2, 3, 4, 5];
        let wrong   = [9u8, 9, 9, 9, 9, 9];
        let (_, image) = setup_wallet_and_capture_image(correct);

        let mut w = ColdWallet::from_disk_image(image, [0x33u8; 32]).unwrap();

        use core::cell::Cell;
        let last_failures: Cell<u8> = Cell::new(255);
        let mut persist = |blob: &[u8; PERSIST_BYTES]| { last_failures.set(blob[1]); };

        // Type wrong PIN by looking up positions in the current pad.
        let order = match w.state {
            AppState::EnterPin { order, .. } => order,
            _ => unreachable!(),
        };
        for &digit in &wrong {
            let pos = order.iter().position(|&d| d == digit).unwrap();
            let (x, y) = pin_key_pos(pos);
            let (event, entropy) = create_touch_event_with_entropy(x + 1, y + 1, 12);
            w.handle_event(event, &mut persist);
            if w.has_pending_work() {
                w.process_pending(entropy, &mut persist);
            }
        }

        assert_eq!(w.failures, 1);
        assert_eq!(last_failures.get(), 1, "failures must be persisted to disk");
        assert!(matches!(w.state, AppState::EnterPin { .. }));
        // Seed/entropy were not populated (AEAD failed).
        assert_eq!(w.seed[0], 0);
        assert_eq!(w.entropy[0], 0);
    }

    #[test]
    fn lockout_state_survives_restart() {
        let correct = [0u8, 1, 2, 3, 4, 5];
        let wrong   = [9u8, 9, 9, 9, 9, 9];
        let (_, image) = setup_wallet_and_capture_image(correct);

        let mut w = ColdWallet::from_disk_image(image, [0x77u8; 32]).unwrap();

        let last_image: core::cell::Cell<[u8; PERSIST_BYTES]> =
            core::cell::Cell::new([0u8; PERSIST_BYTES]);
        let mut persist = |blob: &[u8; PERSIST_BYTES]| { last_image.set(*blob); };

        for _ in 0..PIN_MAX_ATTEMPTS {
            // Look up positions in the current pad (re-shuffled after each failure).
            let order = match w.state {
                AppState::EnterPin { order, .. } => order,
                AppState::PinLocked => break,
                _ => unreachable!(),
            };
            for &digit in &wrong {
                let pos = order.iter().position(|&d| d == digit).unwrap();
                let (x, y) = pin_key_pos(pos);
                let (event, entropy) = create_touch_event_with_entropy(x + 1, y + 1, 13);
                w.handle_event(event, &mut persist);
                if w.has_pending_work() {
                    w.process_pending(entropy, &mut persist);
                }
            }
        }
        assert_eq!(w.state, AppState::PinLocked);
        let final_image = last_image.get();
        assert_eq!(final_image[2], 1, "locked flag must be persisted");

        // Simulate a hard restart with the most recently persisted image.
        let w2 = ColdWallet::from_disk_image(final_image, [0x99u8; 32]).unwrap();
        assert_eq!(w2.state, AppState::PinLocked);
        assert!(w2.locked);
    }

    #[test]
    fn confirm_pin_writes_encrypted_blob() {
        let mut w = ColdWallet::new();
        // Simulate that we just came from EnterPassphrase: seed/entropy populated.
        w.entropy[0] = 0x42;
        w.seed[0]    = 0x42;

        let chosen_pin = [0u8, 1, 2, 3, 4, 5];
        w.state = AppState::ConfirmPin { pin: chosen_pin, order: ORDER, digits: [0u8; 6], len: 0 };

        // Capture the persisted image.
        let mut captured: Option<[u8; PERSIST_BYTES]> = None;
        let mut persist = |blob: &[u8; PERSIST_BYTES]| { captured = Some(*blob); };

        for pos in 0..6 {
            let (x, y) = pin_key_pos(pos);
            let (event, entropy) = create_touch_event_with_entropy(x + 1, y + 1, 99);
            w.handle_event(event, &mut persist);
            if w.has_pending_work() {
                w.process_pending(entropy, &mut persist);
            }
        }

        assert_eq!(w.state, AppState::Home);
        assert!(w.disk_image.is_some());
        let image = captured.expect("persist must have been called");
        let hdr = DiskHeader::parse(&image).expect("v2 header");
        assert_eq!(hdr.failures, 0);
        assert!(!hdr.locked);
        // The salt in the wallet matches the salt in the persisted image.
        assert_eq!(hdr.salt, w.salt);
    }

    // ── M5: scan_error flag ───────────────────────────────────────────────

    #[test]
    fn load_psbt_bad_base64_sets_scan_error() {
        let mut w = ColdWallet::new();
        w.state = AppState::SignScan;
        // Bytes that are not valid base64 (contains characters outside alphabet).
        let bad_b64 = b"!!!not-valid-base64!!!";
        let mut data = [0u8; 512];
        let len = bad_b64.len().min(512);
        data[..len].copy_from_slice(&bad_b64[..len]);
        w.handle_event(WalletEvent::PsbtScanned { data, len }, &mut |_: &_| {});
        assert!(w.scan_error(), "scan_error must be true after bad base64");
        assert_eq!(w.state, AppState::SignScan, "must stay in SignScan");
    }

    #[test]
    fn load_psbt_bad_psbt_bytes_sets_scan_error() {
        let mut w = ColdWallet::new();
        w.state = AppState::SignScan;
        // "AAAA" is valid base64 that decodes to three zero bytes — not a
        // valid PSBT, so ParsedPsbt::parse should return Err.
        let garbage_b64 = b"AAAA";
        let mut data = [0u8; 512];
        data[..garbage_b64.len()].copy_from_slice(garbage_b64);
        w.handle_event(WalletEvent::PsbtScanned { data, len: garbage_b64.len() }, &mut |_: &_| {});
        assert!(w.scan_error(), "scan_error must be true after invalid PSBT bytes");
        assert_eq!(w.state, AppState::SignScan);
    }

    #[test]
    fn load_psbt_navigate_home_clears_scan_error() {
        let mut w = ColdWallet::new();
        w.state = AppState::SignScan;
        // Set scan_error via a bad scan.
        let mut data = [0u8; 512]; data[0] = b'!';
        w.handle_event(WalletEvent::PsbtScanned { data, len: 1 }, &mut |_: &_| {});
        assert!(w.scan_error(), "pre-condition: scan_error should be set");

        // Navigate away to Home via the Back button — scan_error must clear.
        let (home_event, _) = create_touch_event_with_entropy(NAV_PREV_X + 1, NAV_BTN_Y + 1, 77);
        w.handle_event(home_event, &mut |_: &_| {});
        assert_eq!(w.state, AppState::Home);
        assert!(!w.scan_error(), "scan_error must clear when navigating to Home");
    }
}
