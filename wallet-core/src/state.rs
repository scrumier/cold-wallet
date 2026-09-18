//! L'état du wallet : les types de la machine à états, `ColdWallet`, et la
//! boucle `handle_event` qui la fait avancer.
//!
//! Les effets de bord sont délégués : `machine` décide du prochain état,
//! `security` porte le PIN et le chiffrement au repos, `wallet` dérive et
//! signe, `mnemonic` porte la saisie BIP39. `handle_event` est le seul endroit
//! où leur ordre est décidé, et cet ordre est une règle de sécurité : le
//! compteur d'échecs part sur le disque avant toute vérification du PIN.

use crate::crypto::{KEY_LEN, SALT_LEN};
use crate::derive::{DESCRIPTOR_MAX, OWN_KEY_COUNT};
use crate::psbt::{ParsedPsbt, MAX_PSBT_B64, MAX_SIGNED_B64};
use crate::storage::{DiskHeader, PERSIST_BYTES};

mod machine;
mod mnemonic;
mod security;
mod wallet;

// Ré-exports pour les appelants qui passent par `crate::state::…` (`draw/`).
pub use machine::pin_key_pos;
pub(crate) use mnemonic::find_matches;

use machine::{shuffle, step};

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
    Descriptor,
    ShowMnemonic     { page: u8 },
    About,
}

// PsbtScanned carries a full max-size Base64 image; boxing would require
// alloc which we don't have in no_std. The capacity derives from the parser
// limits (see psbt.rs) so the three can never disagree (F-03).
#[allow(clippy::large_enum_variant)]
pub enum WalletEvent {
    Touch { x: i32, y: i32, entropy: [u8; 32] },
    /// A PSBT was successfully decoded by the camera / file reader.
    /// `data` is the raw Base64-encoded PSBT; `len` is the number of valid bytes.
    PsbtScanned { data: [u8; MAX_PSBT_B64], len: usize },
}

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
    /// Tweaked output keys of the derivation window (F-04): receive 0/0..20
    /// then change 1/0..20. Derived whenever the seed becomes available;
    /// `None` before setup/unlock. Used to classify change at review time.
    own_keys:           Option<[[u8; 32]; OWN_KEY_COUNT]>,
    /// BIP386 output descriptor of this wallet (`tr([...]/<0;1>/*)#checksum`),
    /// built whenever the seed becomes available. Public information, but
    /// identifying — zeroized like the rest on drop.
    descriptor:         [u8; DESCRIPTOR_MAX],
    descriptor_len:     usize,

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
            own_keys:           None,
            descriptor:         [0u8; DESCRIPTOR_MAX],
            descriptor_len:     0,
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
        if self.address[0] == b'b' || self.address[0] == b't' {
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

    /// Returns the x-only *tweaked* output keys of the whole derivation
    /// window (receive 0/0..20, change 1/0..20) — the 32-byte witness
    /// programs that can appear in our own P2TR scriptPubKeys. Used by the
    /// sign-review screen to identify change without trusting PSBT metadata.
    pub fn own_output_keys(&self) -> Option<&[[u8; 32]; OWN_KEY_COUNT]> {
        self.own_keys.as_ref()
    }

    /// Returns the BIP386 output descriptor of this wallet, if built. This is
    /// what a watch-only wallet (Sparrow, …) imports to construct PSBTs for
    /// us — without it, no host can start the signing loop.
    pub fn descriptor(&self) -> Option<&str> {
        if self.descriptor_len > 0 {
            core::str::from_utf8(&self.descriptor[..self.descriptor_len]).ok()
        } else {
            None
        }
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
        if let Some(ref mut keys) = self.own_keys {
            for row in keys.iter_mut() {
                zero_sensitive(row);
            }
        }
        zero_sensitive(&mut self.address);
        zero_sensitive(&mut self.signed_psbt_b64);
        zero_sensitive(&mut self.salt);
        zero_sensitive(&mut self.descriptor);

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

/// Overwrites every byte with 0 via volatile writes to prevent dead-store elimination.
fn zero_sensitive<const N: usize>(buf: &mut [u8; N]) {
    for b in buf.iter_mut() {
        // SAFETY: volatile write prevents the compiler from eliding this zeroing.
        unsafe { core::ptr::write_volatile(b, 0); }
    }
}

#[cfg(test)]
mod tests;
