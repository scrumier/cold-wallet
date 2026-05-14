use bip39::Mnemonic;

use crate::keyboard::{passphrase_key_at, KeyPress};
use crate::layout::*;

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
    RestoreWallet,
    EnterPassphrase  { buf: [u8; 32], len: u8 },
    SetPin           { order: [u8; 10], digits: [u8; 6], len: u8 },
    ConfirmPin       { pin: [u8; 6], order: [u8; 10], digits: [u8; 6], len: u8 },
    PinMismatch,
    EnterPin         { order: [u8; 10], digits: [u8; 6], len: u8, gate: PinGate },
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

pub enum WalletEvent {
    Touch { x: i32, y: i32, entropy: [u8; 32] },
}

pub struct ColdWallet {
    pub state: AppState,
    pin: Option<[u8; 6]>,
    words: [&'static str; 24],
}

impl ColdWallet {
    pub fn new() -> Self {
        Self { state: AppState::Welcome, pin: None, words: [""; 24] }
    }

    pub fn get_state(&self) -> AppState {
        self.state
    }

    pub fn mnemonic_words(&self) -> &[&'static str; 24] {
        &self.words
    }

    pub fn handle_event(&mut self, event: WalletEvent) {
        let (new_state, new_pin, new_words) = step(self.state, event, self.pin);
        self.state = new_state;
        if let Some(pin) = new_pin { self.pin = Some(pin); }
        if let Some(words) = new_words { self.words = words; }
    }
}

impl Default for ColdWallet {
    fn default() -> Self { Self::new() }
}

type StepResult = (AppState, Option<[u8; 6]>, Option<[&'static str; 24]>);

fn step(state: AppState, event: WalletEvent, stored_pin: Option<[u8; 6]>) -> StepResult {
    let WalletEvent::Touch { x, y, entropy } = event;
    let seed = u32::from_le_bytes([entropy[0], entropy[1], entropy[2], entropy[3]]);

    match state {
        AppState::Welcome => {
            if in_rect(x, y, BTN_X, BTN_NEW_Y, BTN_W, BTN_H) {
                (AppState::NewWallet { page: 0 }, None, Some(generate_words(&entropy)))
            } else if in_rect(x, y, BTN_X, BTN_RESTORE_Y, BTN_W, BTN_H) {
                (AppState::RestoreWallet, None, None)
            } else {
                (AppState::Welcome, None, None)
            }
        }

        AppState::NewWallet { page } => {
            let prev = in_rect(x, y, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H);
            let next = in_rect(x, y, NAV_NEXT_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H);

            if next && page < 3 {
                (AppState::NewWallet { page: page + 1 }, None, None)
            } else if next && page == 3 {
                (AppState::EnterPassphrase { buf: [0u8; 32], len: 0 }, None, None)
            } else if prev && page > 0 {
                (AppState::NewWallet { page: page - 1 }, None, None)
            } else {
                (AppState::NewWallet { page }, None, None)
            }
        }

        AppState::EnterPassphrase { buf, len } => {
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
            (next.unwrap_or(AppState::EnterPassphrase { buf, len }), None, None)
        }

        AppState::SetPin { order, digits, len } => {
            if let Some(digit) = pin_digit_at(x, y, &order) {
                if len < 6 {
                    let mut d = digits; d[len as usize] = digit;
                    let new_len = len + 1;
                    if new_len == 6 {
                        (AppState::ConfirmPin { pin: d, order: shuffle(seed), digits: [0u8; 6], len: 0 }, None, None)
                    } else {
                        (AppState::SetPin { order, digits: d, len: new_len }, None, None)
                    }
                } else {
                    (AppState::SetPin { order, digits, len }, None, None)
                }
            } else if in_rect(x, y, PIN_DEL_X, PIN_DEL_Y, PIN_DEL_W, PIN_DEL_H) && len > 0 {
                (AppState::SetPin { order, digits, len: len - 1 }, None, None)
            } else {
                (AppState::SetPin { order, digits, len }, None, None)
            }
        }

        AppState::ConfirmPin { pin, order, digits, len } => {
            if let Some(digit) = pin_digit_at(x, y, &order) {
                if len < 6 {
                    let mut d = digits; d[len as usize] = digit;
                    let new_len = len + 1;
                    if new_len == 6 {
                        if d == pin {
                            (AppState::Home, Some(d), None)
                        } else {
                            (AppState::PinMismatch, None, None)
                        }
                    } else {
                        (AppState::ConfirmPin { pin, order, digits: d, len: new_len }, None, None)
                    }
                } else {
                    (AppState::ConfirmPin { pin, order, digits, len }, None, None)
                }
            } else if in_rect(x, y, PIN_DEL_X, PIN_DEL_Y, PIN_DEL_W, PIN_DEL_H) && len > 0 {
                (AppState::ConfirmPin { pin, order, digits, len: len - 1 }, None, None)
            } else {
                (AppState::ConfirmPin { pin, order, digits, len }, None, None)
            }
        }

        AppState::PinMismatch => {
            (AppState::SetPin { order: shuffle(seed), digits: [0u8; 6], len: 0 }, None, None)
        }

        AppState::EnterPin { order, digits, len, gate } => {
            if let Some(digit) = pin_digit_at(x, y, &order) {
                if len < 6 {
                    let mut d = digits; d[len as usize] = digit;
                    let new_len = len + 1;
                    if new_len == 6 {
                        if stored_pin == Some(d) {
                            let next = match gate {
                                PinGate::Unlock       => AppState::Home,
                                PinGate::ShowMnemonic => AppState::ShowMnemonic { page: 0 },
                                PinGate::ChangePin    => AppState::SetPin {
                                    order: shuffle(seed), digits: [0u8; 6], len: 0,
                                },
                            };
                            (next, None, None)
                        } else {
                            (AppState::EnterPin {
                                order: shuffle(seed), digits: [0u8; 6], len: 0, gate,
                            }, None, None)
                        }
                    } else {
                        (AppState::EnterPin { order, digits: d, len: new_len, gate }, None, None)
                    }
                } else {
                    (AppState::EnterPin { order, digits, len, gate }, None, None)
                }
            } else if in_rect(x, y, PIN_DEL_X, PIN_DEL_Y, PIN_DEL_W, PIN_DEL_H) && len > 0 {
                (AppState::EnterPin { order, digits, len: len - 1, gate }, None, None)
            } else {
                (AppState::EnterPin { order, digits, len, gate }, None, None)
            }
        }

        AppState::Home => {
            if in_rect(x, y, HOME_X0, HOME_Y0, HOME_BTN_W, HOME_BTN_H) {
                (AppState::Receive, None, None)
            } else if in_rect(x, y, HOME_X1, HOME_Y0, HOME_BTN_W, HOME_BTN_H) {
                (AppState::SignScan, None, None)
            } else if in_rect(x, y, HOME_X0, HOME_Y1, HOME_BTN_W, HOME_BTN_H) {
                (AppState::Accounts, None, None)
            } else if in_rect(x, y, HOME_X1, HOME_Y1, HOME_BTN_W, HOME_BTN_H) {
                (AppState::Settings, None, None)
            } else {
                (AppState::Home, None, None)
            }
        }

        AppState::Receive => {
            if in_rect(x, y, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H) {
                (AppState::Home, None, None)
            } else {
                (AppState::Receive, None, None)
            }
        }

        AppState::Accounts => {
            if in_rect(x, y, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H) {
                (AppState::Home, None, None)
            } else {
                (AppState::Accounts, None, None)
            }
        }

        AppState::Settings => {
            if in_rect(x, y, SETTINGS_BTN_X, SETTINGS_Y0, SETTINGS_BTN_W, SETTINGS_BTN_H) {
                (AppState::EnterPin {
                    order: shuffle(seed), digits: [0u8; 6], len: 0, gate: PinGate::ShowMnemonic,
                }, None, None)
            } else if in_rect(x, y, SETTINGS_BTN_X, SETTINGS_Y1, SETTINGS_BTN_W, SETTINGS_BTN_H) {
                (AppState::EnterPin {
                    order: shuffle(seed), digits: [0u8; 6], len: 0, gate: PinGate::ChangePin,
                }, None, None)
            } else if in_rect(x, y, SETTINGS_BTN_X, SETTINGS_Y2, SETTINGS_BTN_W, SETTINGS_BTN_H) {
                (AppState::About, None, None)
            } else if in_rect(x, y, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H) {
                (AppState::Home, None, None)
            } else {
                (AppState::Settings, None, None)
            }
        }

        AppState::ShowMnemonic { page } => {
            let prev = in_rect(x, y, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H);
            let next = in_rect(x, y, NAV_NEXT_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H);

            if next && page < 3 {
                (AppState::ShowMnemonic { page: page + 1 }, None, None)
            } else if next && page == 3 {
                (AppState::Settings, None, None)
            } else if prev && page > 0 {
                (AppState::ShowMnemonic { page: page - 1 }, None, None)
            } else if prev {
                (AppState::Settings, None, None)
            } else {
                (AppState::ShowMnemonic { page }, None, None)
            }
        }

        AppState::About => {
            if in_rect(x, y, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H) {
                (AppState::Settings, None, None)
            } else {
                (AppState::About, None, None)
            }
        }

        AppState::SignScan => {
            if in_rect(x, y, SIGN_VF_X, SIGN_VF_Y, SIGN_VF_W, SIGN_VF_H) {
                (AppState::SignReview, None, None)
            } else if in_rect(x, y, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H) {
                (AppState::Home, None, None)
            } else {
                (AppState::SignScan, None, None)
            }
        }

        AppState::SignReview => {
            if in_rect(x, y, NAV_NEXT_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H) {
                (AppState::SignResult, None, None)
            } else if in_rect(x, y, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H) {
                (AppState::Home, None, None)
            } else {
                (AppState::SignReview, None, None)
            }
        }

        AppState::SignResult => {
            if in_rect(x, y, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H) {
                (AppState::Home, None, None)
            } else {
                (AppState::SignResult, None, None)
            }
        }

        _ => (state, None, None),
    }
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

// Fisher-Yates shuffle using LCG — seeded by platform entropy
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

#[cfg(test)]
mod tests {
    use super::*;

    fn touch_event_with_seed(x: i32, y: i32, seed: u32) -> (WalletEvent, [u8; 32]) {
        let mut entropy = [0u8; 32];
        entropy[..4].copy_from_slice(&seed.to_le_bytes());
        (WalletEvent::Touch { x, y, entropy }, entropy)
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
        let (event, entropy) = touch_event_with_seed(BTN_X + 1, BTN_NEW_Y + 1, 42);
        let (state, pin, words) = step(AppState::Welcome, event, None);
        assert_eq!(state, AppState::NewWallet { page: 0 });
        assert!(pin.is_none());
        assert_eq!(words, Some(generate_words(&entropy)));
    }

    #[test]
    fn welcome_restore_wallet() {
        let (event, _) = touch_event_with_seed(BTN_X + 1, BTN_RESTORE_Y + 1, 7);
        let (state, _, words) = step(AppState::Welcome, event, None);
        assert_eq!(state, AppState::RestoreWallet);
        assert!(words.is_none());
    }

    #[test]
    fn new_wallet_navigation() {
        let (event, _) = touch_event_with_seed(NAV_NEXT_X + 1, NAV_BTN_Y + 1, 1);
        let (state, _, _) = step(AppState::NewWallet { page: 0 }, event, None);
        assert_eq!(state, AppState::NewWallet { page: 1 });

        let (event, _) = touch_event_with_seed(NAV_NEXT_X + 1, NAV_BTN_Y + 1, 1);
        let (state, _, _) = step(AppState::NewWallet { page: 3 }, event, None);
        assert_eq!(state, AppState::EnterPassphrase { buf: [0u8; 32], len: 0 });
    }

    #[test]
    fn enter_passphrase_accepts_input_and_skips() {
        let (event, _) = touch_event_with_seed(ROW0_X + 1, ROW0_Y + 1, 9);
        let (state, _, _) = step(AppState::EnterPassphrase { buf: [0u8; 32], len: 0 }, event, None);
        match state {
            AppState::EnterPassphrase { buf, len } => {
                assert_eq!(len, 1);
                assert_eq!(buf[0], b'Q');
            }
            _ => panic!("expected EnterPassphrase"),
        }

        let (event, _) = touch_event_with_seed(PP_SKIP_X + 1, PP_BTN_Y + 1, 9);
        let (state, _, _) = step(AppState::EnterPassphrase { buf: [0u8; 32], len: 0 }, event, None);
        match state {
            AppState::SetPin { len, .. } => assert_eq!(len, 0),
            _ => panic!("expected SetPin"),
        }
    }

    #[test]
    fn set_pin_then_confirm_matches() {
        let order = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut state = AppState::SetPin { order, digits: [0u8; 6], len: 0 };
        for pos in 0..6 {
            let (x, y) = pin_key_pos(pos);
            let (event, _) = touch_event_with_seed(x + 1, y + 1, 3);
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

        let mut state = AppState::ConfirmPin { pin, order, digits: [0u8; 6], len: 0 };
        let mut result_pin = None;
        for pos in 0..6 {
            let (x, y) = pin_key_pos(pos);
            let (event, _) = touch_event_with_seed(x + 1, y + 1, 3);
            let (next_state, new_pin, _) = step(state, event, None);
            state = next_state;
            if new_pin.is_some() { result_pin = new_pin; }
        }
        assert_eq!(state, AppState::Home);
        assert_eq!(result_pin, Some([0, 1, 2, 3, 4, 5]));
    }

    #[test]
    fn confirm_pin_mismatch_flows_to_reset() {
        let order = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let pin = [1u8; 6];
        let mut state = AppState::ConfirmPin { pin, order, digits: [0u8; 6], len: 0 };
        for pos in 0..6 {
            let (x, y) = pin_key_pos(pos);
            let (event, _) = touch_event_with_seed(x + 1, y + 1, 4);
            state = step(state, event, None).0;
        }
        assert_eq!(state, AppState::PinMismatch);

        let (event, _) = touch_event_with_seed(0, 0, 4);
        let (state, _, _) = step(state, event, None);
        match state {
            AppState::SetPin { len, .. } => assert_eq!(len, 0),
            _ => panic!("expected SetPin"),
        }
    }

    #[test]
    fn enter_pin_unlock_gate() {
        let order = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let stored = Some([0, 1, 2, 3, 4, 5]);
        let mut state = AppState::EnterPin { order, digits: [0u8; 6], len: 0, gate: PinGate::Unlock };
        for pos in 0..6 {
            let (x, y) = pin_key_pos(pos);
            let (event, _) = touch_event_with_seed(x + 1, y + 1, 5);
            state = step(state, event, stored).0;
        }
        assert_eq!(state, AppState::Home);
    }
}
