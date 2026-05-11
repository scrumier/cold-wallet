use crate::layout::*;

pub const ROW0: &[u8] = b"QWERTYUIOP";
pub const ROW1: &[u8] = b"ASDFGHJKL";
pub const ROW2: &[u8] = b"ZXCVBNM";

pub enum KeyPress {
    Char(u8),
    Space,
    Backspace,
    Skip,
    Confirm,
}

pub fn passphrase_key_at(x: i32, y: i32) -> Option<KeyPress> {
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
