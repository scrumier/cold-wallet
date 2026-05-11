use crate::keyboard::{passphrase_key_at, KeyPress};
use crate::layout::*;

pub const MNEMONIC: [&str; 24] = [
    "abandon", "ability", "able",    "about",
    "above",   "absent",  "absorb",  "abstract",
    "absurd",  "abuse",   "access",  "accident",
    "account", "accuse",  "achieve", "acid",
    "acoustic","acquire", "across",  "act",
    "action",  "actor",   "actress", "actual",
];

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AppState {
    Welcome,
    NewWallet        { page: u8 },
    RestoreWallet,
    EnterPassphrase  { buf: [u8; 32], len: u8 },
    SetPin           { order: [u8; 10], digits: [u8; 6], len: u8 },
    ConfirmPin       { pin: [u8; 6], order: [u8; 10], digits: [u8; 6], len: u8 },
    PinMismatch,
    EnterPin,
    Home,
    Receive,
    SignScan,
    SignReview,
    SignResult,
    Accounts,
    Settings,
    ShowMnemonic,
    ChangePin,
    About,
}

pub enum WalletEvent {
    Touch { x: i32, y: i32, entropy: u32 },
}

pub struct ColdWallet {
    pub state: AppState,
}

impl ColdWallet {
    pub fn new() -> Self {
        Self { state: AppState::Welcome }
    }

    pub fn get_state(&self) -> AppState {
        self.state
    }

    pub fn handle_event(&mut self, event: WalletEvent) {
        self.state = handle_event(self.state, event);
    }
}

impl Default for ColdWallet {
    fn default() -> Self {
        Self::new()
    }
}

fn handle_event(state: AppState, event: WalletEvent) -> AppState {
    let WalletEvent::Touch { x, y, entropy } = event;

    match state {
        AppState::Welcome => {
            if in_rect(x, y, BTN_X, BTN_NEW_Y, BTN_W, BTN_H) {
                AppState::NewWallet { page: 0 }
            } else if in_rect(x, y, BTN_X, BTN_RESTORE_Y, BTN_W, BTN_H) {
                AppState::RestoreWallet
            } else {
                AppState::Welcome
            }
        }

        AppState::NewWallet { page } => {
            let prev = in_rect(x, y, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H);
            let next = in_rect(x, y, NAV_NEXT_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H);

            if next && page < 3 {
                AppState::NewWallet { page: page + 1 }
            } else if next && page == 3 {
                AppState::EnterPassphrase { buf: [0u8; 32], len: 0 }
            } else if prev && page > 0 {
                AppState::NewWallet { page: page - 1 }
            } else {
                AppState::NewWallet { page }
            }
        }

        AppState::EnterPassphrase { buf, len } => {
            match passphrase_key_at(x, y) {
                Some(KeyPress::Char(c)) if len < 32 => {
                    let mut new_buf = buf;
                    new_buf[len as usize] = c;
                    AppState::EnterPassphrase { buf: new_buf, len: len + 1 }
                }
                Some(KeyPress::Space) if len < 32 => {
                    let mut new_buf = buf;
                    new_buf[len as usize] = b' ';
                    AppState::EnterPassphrase { buf: new_buf, len: len + 1 }
                }
                Some(KeyPress::Backspace) if len > 0 => {
                    AppState::EnterPassphrase { buf, len: len - 1 }
                }
                Some(KeyPress::Confirm) if len > 0 => {
                    AppState::SetPin { order: shuffle(entropy), digits: [0u8; 6], len: 0 }
                }
                Some(KeyPress::Skip) => {
                    AppState::SetPin { order: shuffle(entropy), digits: [0u8; 6], len: 0 }
                }
                _ => AppState::EnterPassphrase { buf, len },
            }
        }

        AppState::SetPin { order, digits, len } => {
            if let Some(digit) = pin_digit_at(x, y, &order) {
                if len < 6 {
                    let mut new_digits = digits;
                    new_digits[len as usize] = digit;
                    let new_len = len + 1;
                    if new_len == 6 {
                        AppState::ConfirmPin {
                            pin: new_digits,
                            order: shuffle(entropy),
                            digits: [0u8; 6],
                            len: 0,
                        }
                    } else {
                        AppState::SetPin { order, digits: new_digits, len: new_len }
                    }
                } else {
                    AppState::SetPin { order, digits, len }
                }
            } else if in_rect(x, y, PIN_DEL_X, PIN_DEL_Y, PIN_DEL_W, PIN_DEL_H) && len > 0 {
                AppState::SetPin { order, digits, len: len - 1 }
            } else {
                AppState::SetPin { order, digits, len }
            }
        }

        AppState::ConfirmPin { pin, order, digits, len } => {
            if let Some(digit) = pin_digit_at(x, y, &order) {
                if len < 6 {
                    let mut new_digits = digits;
                    new_digits[len as usize] = digit;
                    let new_len = len + 1;
                    if new_len == 6 {
                        if new_digits == pin {
                            AppState::Home
                        } else {
                            AppState::PinMismatch
                        }
                    } else {
                        AppState::ConfirmPin { pin, order, digits: new_digits, len: new_len }
                    }
                } else {
                    AppState::ConfirmPin { pin, order, digits, len }
                }
            } else if in_rect(x, y, PIN_DEL_X, PIN_DEL_Y, PIN_DEL_W, PIN_DEL_H) && len > 0 {
                AppState::ConfirmPin { pin, order, digits, len: len - 1 }
            } else {
                AppState::ConfirmPin { pin, order, digits, len }
            }
        }

        AppState::PinMismatch => {
            AppState::SetPin { order: shuffle(entropy), digits: [0u8; 6], len: 0 }
        }

        AppState::Home => {
            if in_rect(x, y, HOME_X0, HOME_Y0, HOME_BTN_W, HOME_BTN_H) {
                AppState::Receive
            } else if in_rect(x, y, HOME_X1, HOME_Y0, HOME_BTN_W, HOME_BTN_H) {
                AppState::SignScan
            } else if in_rect(x, y, HOME_X0, HOME_Y1, HOME_BTN_W, HOME_BTN_H) {
                AppState::Accounts
            } else if in_rect(x, y, HOME_X1, HOME_Y1, HOME_BTN_W, HOME_BTN_H) {
                AppState::Settings
            } else {
                AppState::Home
            }
        }

        _ => state,
    }
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
    for pos in 0..10usize {
        let (kx, ky) = pin_key_pos(pos);
        if in_rect(x, y, kx, ky, PIN_KEY_W, PIN_KEY_H) {
            return Some(order[pos]);
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
