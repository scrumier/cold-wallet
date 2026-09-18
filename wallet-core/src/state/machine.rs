//! Le dispatch de la machine à états : un tap devient un état suivant.
//!
//! Aucun effet de bord ici. Un `step_*` ne fait que lire des coordonnées et
//! rendre l'état d'après ; c'est `handle_event` qui décide, une fois l'état
//! atteint, de déclencher le chiffrement, la persistance ou la signature.

use crate::derive::indices_to_entropy;
use crate::keyboard::{passphrase_key_at, KeyPress};
use crate::layout::*;

use super::mnemonic::{find_matches, generate_words, tapped_suggestion};
use super::{AppState, PinGate, WalletEvent};

// (new_state, pin_to_store, words_to_store, entropy_to_store)
type StepResult = (AppState, Option<[u8; 6]>, Option<[&'static str; 24]>, Option<[u8; 32]>);

fn no_change(state: AppState) -> StepResult {
    (state, None, None, None)
}

// ── State machine dispatch ────────────────────────────────────────────────────

pub(super) fn step(state: AppState, event: WalletEvent, stored_pin: Option<[u8; 6]>) -> StepResult {
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
        AppState::Descriptor =>
            step_descriptor(x, y),
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
        (AppState::Descriptor, None, None, None)
    } else if in_rect(x, y, SETTINGS_BTN_X, SETTINGS_Y3, SETTINGS_BTN_W, SETTINGS_BTN_H) {
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

fn step_descriptor(x: i32, y: i32) -> StepResult {
    if in_rect(x, y, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H) {
        (AppState::Settings, None, None, None)
    } else {
        (AppState::Descriptor, None, None, None)
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

// ── PIN pad: shuffle + hit-testing ───────────────────────────────────────────

/// Fisher-Yates shuffle of the digits 0–9 for the anti-smudge PIN pad.
///
/// Folds all 256 bits of platform entropy into a 64-bit seed, then drives a
/// splitmix64 PRNG for the swaps — far stronger than the previous 32-bit LCG
/// seed (whose state could not even cover the 10! possible pads). On hardware,
/// `entropy` must come from the TRNG; on the simulator it is `getrandom`.
pub fn shuffle(entropy: &[u8; 32]) -> [u8; 10] {
    let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
    for chunk in entropy.as_chunks::<8>().0 {
        s ^= u64::from_le_bytes(*chunk);
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
