#![no_std]

use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::geometry::Point;
use embedded_graphics::mono_font::{ascii::{FONT_10X20, FONT_6X10}, MonoTextStyle};
use embedded_graphics::primitives::{PrimitiveStyle, PrimitiveStyleBuilder, Rectangle};
use embedded_graphics::text::{Alignment::Center, Text};

// Screen dimensions (STM32H747I-DISCO)
const SCREEN_W: i32 = 800;
const SCREEN_H: i32 = 480;

// Welcome screen
const BTN_W: i32         = 300;
const BTN_H: i32         = 60;
const BTN_X: i32         = (SCREEN_W - BTN_W) / 2;
const BTN_NEW_Y: i32     = 170;
const BTN_RESTORE_Y: i32 = 270;

// NewWallet nav buttons
const NAV_BTN_W: i32  = 160;
const NAV_BTN_H: i32  = 50;
const NAV_PREV_X: i32 = 40;
const NAV_NEXT_X: i32 = SCREEN_W - 40 - NAV_BTN_W;
const NAV_BTN_Y: i32  = SCREEN_H - 70;

// QWERTY keyboard
const KEY_W: i32    = 65;
const KEY_H: i32    = 45;
const KEY_GAP: i32  = 5;
const KEY_STEP: i32 = KEY_W + KEY_GAP;
const ROW_STEP: i32 = KEY_H + KEY_GAP;
const KB_Y: i32     = 115;

const ROW0: &[u8] = b"QWERTYUIOP";
const ROW1: &[u8] = b"ASDFGHJKL";
const ROW2: &[u8] = b"ZXCVBNM";

const ROW0_X: i32 = (SCREEN_W - (10 * KEY_W + 9 * KEY_GAP)) / 2;
const ROW1_X: i32 = (SCREEN_W - (9  * KEY_W + 8 * KEY_GAP)) / 2;
const ROW2_X: i32 = (SCREEN_W - (7  * KEY_W + 6 * KEY_GAP)) / 2;

const ROW0_Y: i32 = KB_Y;
const ROW1_Y: i32 = KB_Y + ROW_STEP;
const ROW2_Y: i32 = KB_Y + 2 * ROW_STEP;
const ROW3_Y: i32 = KB_Y + 3 * ROW_STEP;

const SPACE_X: i32 = 200;
const SPACE_W: i32 = 280;
const BKSP_X: i32  = 510;
const BKSP_W: i32  = 250;

const PP_BTN_Y: i32     = 390;
const PP_BTN_H: i32     = 50;
const PP_BTN_W: i32     = 180;
const PP_SKIP_X: i32    = 40;
const PP_CONFIRM_X: i32 = SCREEN_W - 40 - PP_BTN_W;

// PIN numpad (2 rows of 5 keys)
const PIN_KEY_W: i32   = 100;
const PIN_KEY_H: i32   = 80;
const PIN_KEY_GAP: i32 = 20;
const PIN_KEY_STEP: i32 = PIN_KEY_W + PIN_KEY_GAP;
const PIN_ROW_X: i32   = (SCREEN_W - (5 * PIN_KEY_W + 4 * PIN_KEY_GAP)) / 2;
const PIN_ROW0_Y: i32  = 140;
const PIN_ROW1_Y: i32  = PIN_ROW0_Y + PIN_KEY_H + PIN_KEY_GAP;

const PIN_DEL_X: i32 = 40;
const PIN_DEL_W: i32 = 200;
const PIN_DEL_Y: i32 = 360;
const PIN_DEL_H: i32 = 50;

// Home grid (2x2)
const HOME_BTN_W: i32  = 300;
const HOME_BTN_H: i32  = 140;
const HOME_GAP: i32    = 40;
const HOME_X0: i32     = (SCREEN_W - (2 * HOME_BTN_W + HOME_GAP)) / 2;
const HOME_X1: i32     = HOME_X0 + HOME_BTN_W + HOME_GAP;
const HOME_Y0: i32     = (SCREEN_H - (2 * HOME_BTN_H + HOME_GAP)) / 2;
const HOME_Y1: i32     = HOME_Y0 + HOME_BTN_H + HOME_GAP;

// PIN dots display
const DOT_SIZE: i32 = 20;
const DOT_GAP: i32  = 20;
const DOTS_X: i32   = (SCREEN_W - (6 * DOT_SIZE + 5 * DOT_GAP)) / 2;
const DOTS_Y: i32   = 70;

// 24 placeholder words (replaced later by real BIP39 generation)
const MNEMONIC: [&str; 24] = [
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

enum KeyPress {
    Char(u8),
    Space,
    Backspace,
    Skip,
    Confirm,
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
                Some(KeyPress::Skip) | Some(KeyPress::Confirm) if len > 0 => {
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

// Fisher-Yates shuffle using a simple LCG — seeded by platform entropy
fn shuffle(seed: u32) -> [u8; 10] {
    let mut arr = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let mut s   = seed;
    for i in (1..10usize).rev() {
        s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let j = (s >> 16) as usize % (i + 1);
        arr.swap(i, j);
    }
    arr
}

// Returns the digit value pressed in the numpad, or None
fn pin_digit_at(x: i32, y: i32, order: &[u8; 10]) -> Option<u8> {
    for pos in 0..10usize {
        let (kx, ky) = pin_key_pos(pos);
        if in_rect(x, y, kx, ky, PIN_KEY_W, PIN_KEY_H) {
            return Some(order[pos]);
        }
    }
    None
}

fn pin_key_pos(pos: usize) -> (i32, i32) {
    let col = (pos % 5) as i32;
    let row = (pos / 5) as i32;
    let kx  = PIN_ROW_X + col * PIN_KEY_STEP;
    let ky  = if row == 0 { PIN_ROW0_Y } else { PIN_ROW1_Y };
    (kx, ky)
}

fn passphrase_key_at(x: i32, y: i32) -> Option<KeyPress> {
    if y >= ROW0_Y && y < ROW0_Y + KEY_H {
        for (i, &c) in ROW0.iter().enumerate() {
            let kx = ROW0_X + i as i32 * KEY_STEP;
            if x >= kx && x < kx + KEY_W { return Some(KeyPress::Char(c)); }
        }
    }
    if y >= ROW1_Y && y < ROW1_Y + KEY_H {
        for (i, &c) in ROW1.iter().enumerate() {
            let kx = ROW1_X + i as i32 * KEY_STEP;
            if x >= kx && x < kx + KEY_W { return Some(KeyPress::Char(c)); }
        }
    }
    if y >= ROW2_Y && y < ROW2_Y + KEY_H {
        for (i, &c) in ROW2.iter().enumerate() {
            let kx = ROW2_X + i as i32 * KEY_STEP;
            if x >= kx && x < kx + KEY_W { return Some(KeyPress::Char(c)); }
        }
        if x >= BKSP_X && x < BKSP_X + BKSP_W { return Some(KeyPress::Backspace); }
    }
    if y >= ROW3_Y && y < ROW3_Y + KEY_H {
        if x >= SPACE_X && x < SPACE_X + SPACE_W { return Some(KeyPress::Space); }
        if x >= BKSP_X  && x < BKSP_X  + BKSP_W { return Some(KeyPress::Backspace); }
    }
    if y >= PP_BTN_Y && y < PP_BTN_Y + PP_BTN_H {
        if x >= PP_SKIP_X    && x < PP_SKIP_X    + PP_BTN_W { return Some(KeyPress::Skip); }
        if x >= PP_CONFIRM_X && x < PP_CONFIRM_X + PP_BTN_W { return Some(KeyPress::Confirm); }
    }
    None
}

fn in_rect(x: i32, y: i32, rx: i32, ry: i32, rw: i32, rh: i32) -> bool {
    x >= rx && x < rx + rw && y >= ry && y < ry + rh
}

pub fn draw_ui<D>(display: &mut D, state: AppState) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    display.clear(Rgb565::BLACK)?;

    match state {
        AppState::Welcome                          => draw_welcome(display)?,
        AppState::NewWallet { page }               => draw_new_wallet(display, page)?,
        AppState::EnterPassphrase { buf, len }     => draw_enter_passphrase(display, &buf, len)?,
        AppState::SetPin { order, len, .. }        => draw_pin(display, &order, len, false)?,
        AppState::ConfirmPin { order, len, .. }    => draw_pin(display, &order, len, true)?,
        AppState::PinMismatch                      => draw_pin_mismatch(display)?,
        AppState::Home                             => draw_home(display)?,
        _                                          => draw_placeholder(display, state)?,
    }

    Ok(())
}

fn draw_welcome<D>(display: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let s = white_stroke(2);
    let t = white_text();
    draw_button(display, BTN_X, BTN_NEW_Y,     BTN_W, BTN_H, "New Wallet",     s, t)?;
    draw_button(display, BTN_X, BTN_RESTORE_Y, BTN_W, BTN_H, "Restore Wallet", s, t)?;
    Ok(())
}

fn draw_new_wallet<D>(display: &mut D, page: u8) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let btn_s  = white_stroke(2);
    let dim_s  = dim_stroke();
    let btn_t  = white_text();
    let dim_t  = dim_text();
    let num_t  = MonoTextStyle::new(&FONT_6X10, Rgb565::new(20, 40, 20));

    let page_labels = ["Page 1 / 4", "Page 2 / 4", "Page 3 / 4", "Page 4 / 4"];
    Text::with_alignment(page_labels[page as usize], Point::new(SCREEN_W / 2, 30), num_t, Center)
        .draw(display)?;

    let start = (page as usize) * 6;
    for i in 0..6 {
        let idx   = start + i;
        let row_y = 60 + (i as i32) * 58;

        let mut num_buf = [0u8; 4];
        Text::new(fmt_u8(idx as u8 + 1, &mut num_buf), Point::new(80, row_y + 15), num_t)
            .draw(display)?;
        Text::new(MNEMONIC[idx], Point::new(120, row_y + 15), white_text()).draw(display)?;

        Rectangle::new(Point::new(80, row_y + 40), Size::new(640, 1))
            .into_styled(PrimitiveStyleBuilder::new().fill_color(Rgb565::new(6, 12, 6)).build())
            .draw(display)?;
    }

    if page > 0 {
        draw_button(display, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, "< Prev", btn_s, btn_t)?;
    } else {
        draw_button(display, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, "< Prev", dim_s, dim_t)?;
    }

    let next_label = if page == 3 { "Done >" } else { "Next >" };
    draw_button(display, NAV_NEXT_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, next_label, btn_s, btn_t)?;

    Ok(())
}

fn draw_enter_passphrase<D>(display: &mut D, buf: &[u8; 32], len: u8) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let btn_s  = white_stroke(2);
    let key_s  = white_stroke(1);
    let dim_s  = dim_stroke();
    let btn_t  = white_text();
    let dim_t  = dim_text();
    let small  = MonoTextStyle::new(&FONT_6X10, Rgb565::new(20, 40, 20));

    Text::with_alignment("Passphrase (optional)", Point::new(SCREEN_W / 2, 18), small, Center)
        .draw(display)?;

    Rectangle::new(Point::new(40, 28), Size::new(720, 50))
        .into_styled(white_stroke(1))
        .draw(display)?;

    let s = core::str::from_utf8(&buf[..len as usize]).unwrap_or("");
    Text::new(s, Point::new(50, 63), white_text()).draw(display)?;

    draw_key_row(display, ROW0, ROW0_X, ROW0_Y, key_s, btn_t)?;
    draw_key_row(display, ROW1, ROW1_X, ROW1_Y, key_s, btn_t)?;
    draw_key_row(display, ROW2, ROW2_X, ROW2_Y, key_s, btn_t)?;

    draw_button(display, SPACE_X, ROW3_Y, SPACE_W, KEY_H, "SPACE", btn_s, btn_t)?;
    draw_button(display, BKSP_X,  ROW3_Y, BKSP_W,  KEY_H, "<-",    btn_s, btn_t)?;

    draw_button(display, PP_SKIP_X, PP_BTN_Y, PP_BTN_W, PP_BTN_H, "Skip", btn_s, btn_t)?;

    if len > 0 {
        draw_button(display, PP_CONFIRM_X, PP_BTN_Y, PP_BTN_W, PP_BTN_H, "Confirm", btn_s, btn_t)?;
    } else {
        draw_button(display, PP_CONFIRM_X, PP_BTN_Y, PP_BTN_W, PP_BTN_H, "Confirm", dim_s, dim_t)?;
    }

    Ok(())
}

fn draw_pin<D>(display: &mut D, order: &[u8; 10], len: u8, confirm: bool) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let btn_s = white_stroke(2);
    let btn_t = white_text();
    let small = MonoTextStyle::new(&FONT_6X10, Rgb565::new(20, 40, 20));

    let label = if confirm { "Confirm your PIN" } else { "Choose a PIN" };
    Text::with_alignment(label, Point::new(SCREEN_W / 2, 40), small, Center).draw(display)?;

    // 6 dots showing progress
    for i in 0..6i32 {
        let dx = DOTS_X + i * (DOT_SIZE + DOT_GAP);
        let style = if i < len as i32 {
            PrimitiveStyleBuilder::new().fill_color(Rgb565::WHITE).build()
        } else {
            white_stroke(1)
        };
        Rectangle::new(Point::new(dx, DOTS_Y), Size::new(DOT_SIZE as u32, DOT_SIZE as u32))
            .into_styled(style)
            .draw(display)?;
    }

    // 10 digit keys — 2 rows of 5
    let mut digit_buf = [0u8; 2];
    for pos in 0..10usize {
        let (kx, ky) = pin_key_pos(pos);
        Rectangle::new(Point::new(kx, ky), Size::new(PIN_KEY_W as u32, PIN_KEY_H as u32))
            .into_styled(white_stroke(2))
            .draw(display)?;

        digit_buf[0] = b'0' + order[pos];
        let s = core::str::from_utf8(&digit_buf[..1]).unwrap_or("?");
        Text::with_alignment(s, Point::new(kx + PIN_KEY_W / 2, ky + PIN_KEY_H / 2 + 7), btn_t, Center)
            .draw(display)?;
    }

    // Delete button
    if len > 0 {
        draw_button(display, PIN_DEL_X, PIN_DEL_Y, PIN_DEL_W, PIN_DEL_H, "<- Del", btn_s, btn_t)?;
    }

    Ok(())
}

fn draw_key_row<D>(
    display: &mut D,
    keys: &[u8],
    x_start: i32,
    y: i32,
    rect_style: PrimitiveStyle<Rgb565>,
    text_style: MonoTextStyle<Rgb565>,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let mut label = [0u8; 1];
    for (i, &c) in keys.iter().enumerate() {
        let kx = x_start + i as i32 * KEY_STEP;
        Rectangle::new(Point::new(kx, y), Size::new(KEY_W as u32, KEY_H as u32))
            .into_styled(rect_style)
            .draw(display)?;
        label[0] = c;
        let s = core::str::from_utf8(&label).unwrap_or("?");
        Text::with_alignment(s, Point::new(kx + KEY_W / 2, y + KEY_H / 2 + 7), text_style, Center)
            .draw(display)?;
    }
    Ok(())
}

fn draw_home<D>(display: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let s = white_stroke(2);
    let t = white_text();

    draw_button(display, HOME_X0, HOME_Y0, HOME_BTN_W, HOME_BTN_H, "Receive",  s, t)?;
    draw_button(display, HOME_X1, HOME_Y0, HOME_BTN_W, HOME_BTN_H, "Sign",     s, t)?;
    draw_button(display, HOME_X0, HOME_Y1, HOME_BTN_W, HOME_BTN_H, "Accounts", s, t)?;
    draw_button(display, HOME_X1, HOME_Y1, HOME_BTN_W, HOME_BTN_H, "Settings", s, t)?;

    Ok(())
}

fn draw_pin_mismatch<D>(display: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let red   = MonoTextStyle::new(&FONT_10X20, Rgb565::RED);
    let small = MonoTextStyle::new(&FONT_6X10,  Rgb565::new(20, 40, 20));

    Text::with_alignment("Wrong PIN", Point::new(SCREEN_W / 2, SCREEN_H / 2 - 20), red, Center)
        .draw(display)?;
    Text::with_alignment("Tap anywhere to retry", Point::new(SCREEN_W / 2, SCREEN_H / 2 + 20), small, Center)
        .draw(display)?;

    Ok(())
}

fn draw_placeholder<D>(display: &mut D, state: AppState) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let label = match state {
        AppState::RestoreWallet => "Restore Wallet",
        AppState::EnterPin      => "Enter PIN",
        AppState::Home          => "Home",
        AppState::Receive       => "Receive",
        AppState::SignScan      => "Scan QR",
        AppState::SignReview    => "Review TX",
        AppState::SignResult    => "Signed QR",
        AppState::Accounts      => "Accounts",
        AppState::Settings      => "Settings",
        AppState::ShowMnemonic  => "Show Mnemonic",
        AppState::ChangePin     => "Change PIN",
        AppState::About         => "About",
        _                       => "—",
    };

    Text::with_alignment(label, Point::new(SCREEN_W / 2, SCREEN_H / 2), white_text(), Center)
        .draw(display)?;

    Ok(())
}

fn draw_button<D>(
    display: &mut D,
    x: i32, y: i32, w: i32, h: i32,
    label: &str,
    rect_style: PrimitiveStyle<Rgb565>,
    text_style: MonoTextStyle<Rgb565>,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    Rectangle::new(Point::new(x, y), Size::new(w as u32, h as u32))
        .into_styled(rect_style)
        .draw(display)?;

    Text::with_alignment(label, Point::new(x + w / 2, y + h / 2 + 7), text_style, Center)
        .draw(display)?;

    Ok(())
}

// Style helpers
fn white_stroke(width: u32) -> PrimitiveStyle<Rgb565> {
    PrimitiveStyleBuilder::new().stroke_color(Rgb565::WHITE).stroke_width(width).build()
}

fn dim_stroke() -> PrimitiveStyle<Rgb565> {
    PrimitiveStyleBuilder::new().stroke_color(Rgb565::new(10, 20, 10)).stroke_width(2).build()
}

fn white_text() -> MonoTextStyle<'static, Rgb565> {
    MonoTextStyle::new(&FONT_10X20, Rgb565::WHITE)
}

fn dim_text() -> MonoTextStyle<'static, Rgb565> {
    MonoTextStyle::new(&FONT_10X20, Rgb565::new(10, 20, 10))
}

fn fmt_u8(n: u8, buf: &mut [u8; 4]) -> &str {
    let mut pos = 4usize;
    let mut val = n;
    loop {
        pos -= 1;
        buf[pos] = b'0' + (val % 10);
        val /= 10;
        if val == 0 { break; }
    }
    core::str::from_utf8(&buf[pos..]).unwrap_or("?")
}
