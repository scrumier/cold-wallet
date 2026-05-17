use bip39::Mnemonic;

use crate::base64;
use crate::derive::{indices_to_entropy, taproot_address};
use crate::keyboard::{passphrase_key_at, KeyPress};
use crate::layout::*;
use crate::psbt::{self, ParsedPsbt, MAX_PSBT_RAW};
use crate::signing::sign_psbt;

// Lock the wallet permanently after this many consecutive wrong PIN attempts.
const PIN_MAX_ATTEMPTS: u8 = 3;

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
    EnterPin         { order: [u8; 10], digits: [u8; 6], len: u8, gate: PinGate, failures: u8 },
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
    ChangePin,
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

    /// Returns the currently loaded PSBT, if any.
    pub fn current_psbt(&self) -> Option<&ParsedPsbt> { self.psbt.as_ref() }

    /// Returns the signed PSBT as a Base64 string, if signing has completed.
    pub fn signed_psbt_b64(&self) -> Option<&str> {
        if self.signed_psbt_b64_len > 0 {
            core::str::from_utf8(&self.signed_psbt_b64[..self.signed_psbt_b64_len]).ok()
        } else {
            None
        }
    }

    pub fn handle_event(&mut self, event: WalletEvent) {
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

        // Sign the PSBT when user confirms on the review screen.
        // Pass the touch-event entropy as BIP340 aux_rand for fault-injection resistance.
        if matches!(prev, AppState::SignReview)
            && matches!(self.state, AppState::SignResult)
        {
            self.do_sign(&touch_entropy);
        }

        // Clear PSBT state when navigating back to Home.
        if matches!(self.state, AppState::Home) {
            self.psbt = None;
            self.signed_psbt_b64_len = 0;
        }
    }

    fn derive_address(&mut self, passphrase: &str) {
        if let Ok(m) = Mnemonic::from_entropy(&self.entropy) {
            let seed = m.to_seed_normalized(passphrase);
            debug_assert!(taproot_address(&seed).is_some(), "taproot derivation failed");
            if let Some(addr) = taproot_address(&seed) {
                self.address = addr;
                self.seed    = seed;
            }
        }
    }

    /// Decodes a Base64 PSBT, parses it, and transitions to SignReview on success.
    fn load_psbt(&mut self, b64: &[u8]) {
        let mut raw = [0u8; MAX_PSBT_RAW];
        let Some(raw_len) = base64::decode(b64, &mut raw) else { return };
        if let Ok(parsed) = ParsedPsbt::parse(&raw[..raw_len]) {
            self.psbt = Some(parsed);
            self.state = AppState::SignReview;
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
        zero_sensitive(&mut self.address);
        zero_sensitive(&mut self.signed_psbt_b64);
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

// (new_state, pin_to_store, words_to_store, entropy_to_store)
type StepResult = (AppState, Option<[u8; 6]>, Option<[&'static str; 24]>, Option<[u8; 32]>);

fn no_change(state: AppState) -> StepResult {
    (state, None, None, None)
}

// ── State machine dispatch ────────────────────────────────────────────────────

fn step(state: AppState, event: WalletEvent, stored_pin: Option<[u8; 6]>) -> StepResult {
    // PsbtScanned is handled before step() is called (early return in handle_event).
    let WalletEvent::Touch { x, y, entropy } = event else { return no_change(state) };
    let seed = u32::from_le_bytes([entropy[0], entropy[1], entropy[2], entropy[3]]);

    match state {
        AppState::Welcome =>
            step_welcome(x, y, &entropy, seed),
        AppState::NewWallet { page } =>
            step_new_wallet(x, y, seed, page),
        AppState::EnterPassphrase { buf, len } =>
            step_enter_passphrase(x, y, seed, buf, len),
        AppState::SetPin { order, digits, len } =>
            step_set_pin(x, y, seed, order, digits, len),
        AppState::ConfirmPin { pin, order, digits, len } =>
            step_confirm_pin(x, y, seed, pin, order, digits, len),
        AppState::PinMismatch =>
            step_pin_mismatch(seed),
        AppState::EnterPin { order, digits, len, gate, failures } =>
            step_enter_pin(x, y, seed, order, digits, len, gate, failures, stored_pin),
        AppState::Home =>
            step_home(x, y),
        AppState::Receive =>
            step_receive(x, y),
        AppState::Accounts =>
            step_accounts(x, y),
        AppState::Settings =>
            step_settings(x, y, seed),
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
        // Terminal / not-yet-implemented states accept no input.
        AppState::PinLocked | AppState::ChangePin =>
            no_change(state),
    }
}

// ── Per-state handlers ────────────────────────────────────────────────────────

fn step_welcome(x: i32, y: i32, entropy: &[u8; 32], _seed: u32) -> StepResult {
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

fn step_new_wallet(x: i32, y: i32, seed: u32, page: u8) -> StepResult {
    let is_prev = in_rect(x, y, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H);
    let is_next = in_rect(x, y, NAV_NEXT_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H);

    if is_next && page < 3 {
        (AppState::NewWallet { page: page + 1 }, None, None, None)
    } else if is_next && page == 3 {
        (AppState::EnterPassphrase { buf: [0u8; 32], len: 0 }, None, None, None)
    } else if is_prev && page > 0 {
        (AppState::NewWallet { page: page - 1 }, None, None, None)
    } else {
        let _ = seed;
        (AppState::NewWallet { page }, None, None, None)
    }
}

fn step_enter_passphrase(x: i32, y: i32, seed: u32, buf: [u8; 32], len: u8) -> StepResult {
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
            Some(AppState::SetPin { order: shuffle(seed), digits: [0u8; 6], len: 0 }),
        Some(KeyPress::Skip) =>
            Some(AppState::SetPin { order: shuffle(seed), digits: [0u8; 6], len: 0 }),
        _ => None,
    };
    (next.unwrap_or(AppState::EnterPassphrase { buf, len }), None, None, None)
}

fn step_set_pin(x: i32, y: i32, seed: u32, order: [u8; 10], mut digits: [u8; 6], len: u8) -> StepResult {
    if let Some(digit) = pin_digit_at(x, y, &order) {
        if len < 6 {
            digits[len as usize] = digit;
            let new_len = len + 1;
            if new_len == 6 {
                (AppState::ConfirmPin { pin: digits, order: shuffle(seed), digits: [0u8; 6], len: 0 }, None, None, None)
            } else {
                (AppState::SetPin { order, digits, len: new_len }, None, None, None)
            }
        } else {
            (AppState::SetPin { order, digits, len }, None, None, None)
        }
    } else if in_rect(x, y, PIN_DEL_X, PIN_DEL_Y, PIN_DEL_W, PIN_DEL_H) && len > 0 {
        (AppState::SetPin { order, digits, len: len - 1 }, None, None, None)
    } else {
        let _ = seed;
        (AppState::SetPin { order, digits, len }, None, None, None)
    }
}

fn step_confirm_pin(x: i32, y: i32, seed: u32, pin: [u8; 6], order: [u8; 10], mut digits: [u8; 6], len: u8) -> StepResult {
    if let Some(digit) = pin_digit_at(x, y, &order) {
        if len < 6 {
            digits[len as usize] = digit;
            let new_len = len + 1;
            if new_len == 6 {
                let matched = digits == pin;
                // Copy the confirmed pin before zeroing both buffers.
                let confirmed_pin = digits;
                zero_sensitive(&mut digits);
                let mut pin_copy = pin;
                zero_sensitive(&mut pin_copy);
                if matched {
                    (AppState::Home, Some(confirmed_pin), None, None)
                } else {
                    (AppState::PinMismatch, None, None, None)
                }
            } else {
                (AppState::ConfirmPin { pin, order, digits, len: new_len }, None, None, None)
            }
        } else {
            (AppState::ConfirmPin { pin, order, digits, len }, None, None, None)
        }
    } else if in_rect(x, y, PIN_DEL_X, PIN_DEL_Y, PIN_DEL_W, PIN_DEL_H) && len > 0 {
        (AppState::ConfirmPin { pin, order, digits, len: len - 1 }, None, None, None)
    } else {
        let _ = seed;
        (AppState::ConfirmPin { pin, order, digits, len }, None, None, None)
    }
}

fn step_pin_mismatch(seed: u32) -> StepResult {
    (AppState::SetPin { order: shuffle(seed), digits: [0u8; 6], len: 0 }, None, None, None)
}

#[allow(clippy::too_many_arguments)]
fn step_enter_pin(
    x: i32, y: i32, seed: u32,
    order: [u8; 10], mut digits: [u8; 6], len: u8,
    gate: PinGate, failures: u8,
    stored_pin: Option<[u8; 6]>,
) -> StepResult {
    if let Some(digit) = pin_digit_at(x, y, &order) {
        if len < 6 {
            digits[len as usize] = digit;
            let new_len = len + 1;
            if new_len == 6 {
                let correct = stored_pin == Some(digits);
                zero_sensitive(&mut digits);
                if correct {
                    let next = match gate {
                        PinGate::Unlock       => AppState::Home,
                        PinGate::ShowMnemonic => AppState::ShowMnemonic { page: 0 },
                        PinGate::ChangePin    => AppState::SetPin {
                            order: shuffle(seed), digits: [0u8; 6], len: 0,
                        },
                    };
                    (next, None, None, None)
                } else {
                    let new_failures = failures + 1;
                    if new_failures >= PIN_MAX_ATTEMPTS {
                        (AppState::PinLocked, None, None, None)
                    } else {
                        (AppState::EnterPin {
                            order: shuffle(seed), digits: [0u8; 6], len: 0,
                            gate, failures: new_failures,
                        }, None, None, None)
                    }
                }
            } else {
                (AppState::EnterPin { order, digits, len: new_len, gate, failures }, None, None, None)
            }
        } else {
            (AppState::EnterPin { order, digits, len, gate, failures }, None, None, None)
        }
    } else if in_rect(x, y, PIN_DEL_X, PIN_DEL_Y, PIN_DEL_W, PIN_DEL_H) && len > 0 {
        (AppState::EnterPin { order, digits, len: len - 1, gate, failures }, None, None, None)
    } else {
        (AppState::EnterPin { order, digits, len, gate, failures }, None, None, None)
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

fn step_settings(x: i32, y: i32, seed: u32) -> StepResult {
    if in_rect(x, y, SETTINGS_BTN_X, SETTINGS_Y0, SETTINGS_BTN_W, SETTINGS_BTN_H) {
        (AppState::EnterPin {
            order: shuffle(seed), digits: [0u8; 6], len: 0,
            gate: PinGate::ShowMnemonic, failures: 0,
        }, None, None, None)
    } else if in_rect(x, y, SETTINGS_BTN_X, SETTINGS_Y1, SETTINGS_BTN_W, SETTINGS_BTN_H) {
        (AppState::EnterPin {
            order: shuffle(seed), digits: [0u8; 6], len: 0,
            gate: PinGate::ChangePin, failures: 0,
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
    // Viewfinder tap is handled as WalletEvent::PsbtScanned by the host (simulator / hardware).
    // Only Cancel is handled here.
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

/// Fisher-Yates shuffle using LCG seeded by platform-provided entropy.
pub fn shuffle(seed: u32) -> [u8; 10] {
    let mut arr = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let mut s   = seed;
    for i in (1..10usize).rev() {
        s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let j = (s >> 16) as usize % (i + 1);
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
        // "ab" should match "abandon", "ability", "able" — the first 3 BIP39 words starting with "ab".
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
        // Tap 'Q' on keyboard (ROW0_X + 1, ROW0_Y + 1) → stored as 'q' (lowercase)
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
        // BKSP_X overlaps the 'B' key at ROW2 — use a coordinate clearly past all letter keys.
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
    fn restore_wallet_full_round_trip() {
        // Encode a known entropy, get the 24 word indices, simulate tapping each
        // suggestion (index 0 in suggestions = word_list[idx]) through the state machine.
        let entropy = [0x11u8; 32];
        let m = bip39::Mnemonic::from_entropy(&entropy).unwrap();
        let word_list = bip39::Language::English.word_list();
        let mut word_indices = [0u16; 24];
        for (i, word) in m.words().enumerate() {
            word_indices[i] = word_list.iter().position(|&w| w == word).unwrap() as u16;
        }

        let mut state = AppState::RestoreWallet {
            word_idx: 0, buf: [0u8; 8], buf_len: 0, confirmed: [0u16; 24], error: false,
        };

        for wi in 0..24usize {
            let target = word_indices[wi];
            let target_word = word_list[target as usize];

            // Type enough chars so the target appears as suggestions[0].
            // We type up to 4 chars of the word until suggestions[0] == target.
            for char_count in 1..=target_word.len().min(8) {
                let prefix = &target_word.as_bytes()[..char_count];
                let mut buf = [0u8; 8];
                buf[..char_count].copy_from_slice(prefix);
                let matches = find_matches(&buf, char_count as u8);
                if matches[0] == Some(target) {
                    // Set state with this prefix then tap suggestion 0
                    if let AppState::RestoreWallet { word_idx, confirmed, .. } = state {
                        state = AppState::RestoreWallet {
                            word_idx, buf, buf_len: char_count as u8, confirmed, error: false,
                        };
                    }
                    break;
                }
            }

            // Tap suggestion button 0
            let (event, _) = create_touch_event_with_entropy(
                RESTORE_SUGGEST_X0 + 1, RESTORE_SUGGEST_Y + 1, 42,
            );
            let (new_state, _, _, _) = step(state, event, None);
            state = new_state;
        }

        // After 24 words, should transition to EnterPassphrase with correct entropy
        assert!(matches!(state, AppState::EnterPassphrase { .. }));
    }

    #[test]
    fn in_rect_bounds() {
        assert!(in_rect(0, 0, 0, 0, 1, 1));
        assert!(!in_rect(1, 0, 0, 0, 1, 1));
        assert!(!in_rect(0, 1, 0, 0, 1, 1));
    }

    #[test]
    fn shuffle_is_permutation() {
        let order = shuffle(0x1234_5678);
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
    fn welcome_new_wallet_generates_words() {
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

    #[test]
    fn welcome_restore_wallet() {
        let (event, _) = create_touch_event_with_entropy(BTN_X + 1, BTN_RESTORE_Y + 1, 7);
        let (state, _, words, entropy) = step(AppState::Welcome, event, None);
        assert!(matches!(state, AppState::RestoreWallet { word_idx: 0, buf_len: 0, .. }));
        assert!(words.is_none());
        assert!(entropy.is_none());
    }

    #[test]
    fn new_wallet_navigation() {
        let (event, _) = create_touch_event_with_entropy(NAV_NEXT_X + 1, NAV_BTN_Y + 1, 1);
        let (state, _, _, _) = step(AppState::NewWallet { page: 0 }, event, None);
        assert_eq!(state, AppState::NewWallet { page: 1 });

        let (event, _) = create_touch_event_with_entropy(NAV_NEXT_X + 1, NAV_BTN_Y + 1, 1);
        let (state, _, _, _) = step(AppState::NewWallet { page: 3 }, event, None);
        assert_eq!(state, AppState::EnterPassphrase { buf: [0u8; 32], len: 0 });
    }

    #[test]
    fn enter_passphrase_accepts_input_and_skips() {
        let (event, _) = create_touch_event_with_entropy(ROW0_X + 1, ROW0_Y + 1, 9);
        let (state, _, _, _) = step(AppState::EnterPassphrase { buf: [0u8; 32], len: 0 }, event, None);
        match state {
            AppState::EnterPassphrase { buf, len } => {
                assert_eq!(len, 1);
                assert_eq!(buf[0], b'Q');
            }
            _ => panic!("expected EnterPassphrase"),
        }

        let (event, _) = create_touch_event_with_entropy(PP_SKIP_X + 1, PP_BTN_Y + 1, 9);
        let (state, _, _, _) = step(AppState::EnterPassphrase { buf: [0u8; 32], len: 0 }, event, None);
        match state {
            AppState::SetPin { len, .. } => assert_eq!(len, 0),
            _ => panic!("expected SetPin"),
        }
    }

    #[test]
    fn passphrase_buffer_limits_input() {
        let buf = [b'A'; 32];
        let (event, _) = create_touch_event_with_entropy(ROW0_X + 1, ROW0_Y + 1, 10);
        let (state, _, _, _) = step(AppState::EnterPassphrase { buf, len: 32 }, event, None);
        match state {
            AppState::EnterPassphrase { buf: next_buf, len } => {
                assert_eq!(len, 32);
                assert_eq!(next_buf, buf);
            }
            _ => panic!("expected EnterPassphrase"),
        }
    }

    #[test]
    fn set_pin_then_confirm_matches() {
        let mut state = AppState::SetPin { order: ORDER, digits: [0u8; 6], len: 0 };
        for pos in 0..6 {
            let (x, y) = pin_key_pos(pos);
            let (event, _) = create_touch_event_with_entropy(x + 1, y + 1, 3);
            state = step(state, event, None).0;
        }
        let pin = match state {
            AppState::ConfirmPin { pin, len, .. } => {
                assert_eq!(len, 0);
                pin
            }
            _ => panic!("expected ConfirmPin"),
        };
        assert_eq!(pin, [0, 1, 2, 3, 4, 5]);

        let mut state = AppState::ConfirmPin { pin, order: ORDER, digits: [0u8; 6], len: 0 };
        let mut result_pin = None;
        for pos in 0..6 {
            let (x, y) = pin_key_pos(pos);
            let (event, _) = create_touch_event_with_entropy(x + 1, y + 1, 3);
            let (next_state, new_pin, _, _) = step(state, event, None);
            state = next_state;
            result_pin = result_pin.or(new_pin);
        }
        assert_eq!(state, AppState::Home);
        assert_eq!(result_pin, Some([0, 1, 2, 3, 4, 5]));
    }

    #[test]
    fn set_pin_respects_custom_order() {
        let order = [5u8, 4, 3, 2, 1, 0, 9, 8, 7, 6];
        let mut state = AppState::SetPin { order, digits: [0u8; 6], len: 0 };
        for pos in 0..6 {
            let (x, y) = pin_key_pos(pos);
            let (event, _) = create_touch_event_with_entropy(x + 1, y + 1, 11);
            state = step(state, event, None).0;
        }
        match state {
            AppState::ConfirmPin { pin, .. } => {
                assert_eq!(pin, [5, 4, 3, 2, 1, 0]);
            }
            _ => panic!("expected ConfirmPin"),
        }
    }

    #[test]
    fn confirm_pin_mismatch_flows_to_reset() {
        let pin = [1u8; 6];
        let mut state = AppState::ConfirmPin { pin, order: ORDER, digits: [0u8; 6], len: 0 };
        for pos in 0..6 {
            let (x, y) = pin_key_pos(pos);
            let (event, _) = create_touch_event_with_entropy(x + 1, y + 1, 4);
            state = step(state, event, None).0;
        }
        assert_eq!(state, AppState::PinMismatch);

        let (event, _) = create_touch_event_with_entropy(0, 0, 4);
        let (state, _, _, _) = step(state, event, None);
        match state {
            AppState::SetPin { len, .. } => assert_eq!(len, 0),
            _ => panic!("expected SetPin"),
        }
    }

    #[test]
    fn enter_pin_unlock_gate() {
        let stored_pin = Some([0, 1, 2, 3, 4, 5]);
        let mut state = AppState::EnterPin { order: ORDER, digits: [0u8; 6], len: 0, gate: PinGate::Unlock, failures: 0 };
        for pos in 0..6 {
            let (x, y) = pin_key_pos(pos);
            let (event, _) = create_touch_event_with_entropy(x + 1, y + 1, 5);
            state = step(state, event, stored_pin).0;
        }
        assert_eq!(state, AppState::Home);
    }

    #[test]
    fn enter_pin_show_mnemonic_gate() {
        let stored_pin = Some([0, 1, 2, 3, 4, 5]);
        let mut state = AppState::EnterPin { order: ORDER, digits: [0u8; 6], len: 0, gate: PinGate::ShowMnemonic, failures: 0 };
        for pos in 0..6 {
            let (x, y) = pin_key_pos(pos);
            let (event, _) = create_touch_event_with_entropy(x + 1, y + 1, 12);
            state = step(state, event, stored_pin).0;
        }
        assert_eq!(state, AppState::ShowMnemonic { page: 0 });
    }

    #[test]
    fn enter_pin_change_pin_gate() {
        let stored_pin = Some([0, 1, 2, 3, 4, 5]);
        let mut state = AppState::EnterPin { order: ORDER, digits: [0u8; 6], len: 0, gate: PinGate::ChangePin, failures: 0 };
        for pos in 0..6 {
            let (x, y) = pin_key_pos(pos);
            let (event, _) = create_touch_event_with_entropy(x + 1, y + 1, 13);
            state = step(state, event, stored_pin).0;
        }
        match state {
            AppState::SetPin { len, .. } => assert_eq!(len, 0),
            _ => panic!("expected SetPin"),
        }
    }

    #[test]
    fn enter_pin_rejects_mismatch() {
        let stored_pin = Some([0, 1, 2, 3, 4, 5]);
        let mut state = AppState::EnterPin { order: ORDER, digits: [0u8; 6], len: 0, gate: PinGate::Unlock, failures: 0 };
        for pos in [1usize, 2, 3, 4, 5, 6] {
            let (x, y) = pin_key_pos(pos);
            let (event, _) = create_touch_event_with_entropy(x + 1, y + 1, 6);
            state = step(state, event, stored_pin).0;
        }
        match state {
            AppState::EnterPin { len, gate, failures, .. } => {
                assert_eq!(len, 0);
                assert_eq!(gate, PinGate::Unlock);
                assert_eq!(failures, 1);
            }
            _ => panic!("expected EnterPin"),
        }
    }

    #[test]
    fn enter_pin_lockout_after_max_attempts() {
        let stored_pin = Some([0, 1, 2, 3, 4, 5]);
        // Wrong PIN positions: tapping pos 1..6 gives digits [1,2,3,4,5,6] ≠ [0,1,2,3,4,5]
        let wrong_positions = [1usize, 2, 3, 4, 5, 6];

        let mut state = AppState::EnterPin {
            order: ORDER, digits: [0u8; 6], len: 0,
            gate: PinGate::Unlock, failures: 0,
        };

        for attempt in 0..PIN_MAX_ATTEMPTS {
            for &pos in &wrong_positions {
                let (x, y) = pin_key_pos(pos);
                let (event, _) = create_touch_event_with_entropy(x + 1, y + 1, 6);
                state = step(state, event, stored_pin).0;
            }
            if attempt < PIN_MAX_ATTEMPTS - 1 {
                // Still in EnterPin with incremented failures
                assert!(matches!(state, AppState::EnterPin { .. }), "should still be in EnterPin after attempt {attempt}");
            }
        }

        assert_eq!(state, AppState::PinLocked);
    }
}
