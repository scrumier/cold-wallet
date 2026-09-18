//! Tests de la machine à états, du PIN et de la persistance.
//!
//! Ils vivent à côté du code qu'ils testent (`#[cfg(test)] mod tests;` dans
//! `state.rs`) parce qu'ils touchent des champs privés de `ColdWallet`.

use crate::crypto::{KEY_LEN, NONCE_LEN, SALT_LEN};
use crate::layout::*;
use crate::psbt::MAX_PSBT_B64;
use crate::storage::{encrypt_into_blob, DiskHeader, Secrets, PERSIST_BYTES};

use super::machine::{in_rect, pin_digit_at, pin_key_pos, shuffle, step};
use super::mnemonic::{find_matches, generate_words};
use super::{AppState, ColdWallet, PinGate, WalletEvent, PIN_MAX_ATTEMPTS};

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
    for chunk in entropy.as_chunks_mut::<4>().0 {
        s = s.wrapping_mul(LCG_MULTIPLIER).wrapping_add(LCG_INCREMENT);
        *chunk = s.to_le_bytes();
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

/// Where a tap aimed at a PIN key would land if it were handled from Home.
/// `None` means it falls in a gap between the Home buttons.
fn home_hit_from_pin_key(pos: usize) -> Option<AppState> {
    let (kx, ky) = pin_key_pos(pos);
    let (event, _) = create_touch_event_with_entropy(
        kx + PIN_KEY_W / 2, ky + PIN_KEY_H / 2, 3,
    );
    let (state, ..) = step(AppState::Home, event, None);
    (state != AppState::Home).then_some(state)
}

#[test]
fn pin_pad_keys_sit_on_top_of_the_home_grid() {
    // Both grids are centred on the same 800×480 screen, so the PIN pad and the
    // Home buttons share pixels. This is why `wallet-sim` swallows the clicks
    // queued behind a screen change: the tap that validates the 6th digit is
    // also a tap on a Home button, and a second click during the ~1.5 s PBKDF2
    // pass would otherwise open SignScan straight after unlocking.
    // Pinning the geometry here: removing the overlap should be a decision.
    assert_eq!(home_hit_from_pin_key(0), Some(AppState::Receive));
    assert_eq!(home_hit_from_pin_key(3), Some(AppState::SignScan));
    assert_eq!(home_hit_from_pin_key(5), Some(AppState::Accounts));
    assert_eq!(home_hit_from_pin_key(9), Some(AppState::Settings));
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
    let mut data = [0u8; MAX_PSBT_B64];
    let len = bad_b64.len().min(data.len());
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
    let mut data = [0u8; MAX_PSBT_B64];
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
    let mut data = [0u8; MAX_PSBT_B64]; data[0] = b'!';
    w.handle_event(WalletEvent::PsbtScanned { data, len: 1 }, &mut |_: &_| {});
    assert!(w.scan_error(), "pre-condition: scan_error should be set");

    // Navigate away to Home via the Back button — scan_error must clear.
    let (home_event, _) = create_touch_event_with_entropy(NAV_PREV_X + 1, NAV_BTN_Y + 1, 77);
    w.handle_event(home_event, &mut |_: &_| {});
    assert_eq!(w.state, AppState::Home);
    assert!(!w.scan_error(), "scan_error must clear when navigating to Home");
}
