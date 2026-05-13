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
    if (ROW0_Y..ROW0_Y + KEY_H).contains(&y) {
        for (i, &c) in ROW0.iter().enumerate() {
            let kx = ROW0_X + i as i32 * KEY_STEP;
            if (kx..kx + KEY_W).contains(&x) { return Some(KeyPress::Char(c)); }
        }
    }
    if (ROW1_Y..ROW1_Y + KEY_H).contains(&y) {
        for (i, &c) in ROW1.iter().enumerate() {
            let kx = ROW1_X + i as i32 * KEY_STEP;
            if (kx..kx + KEY_W).contains(&x) { return Some(KeyPress::Char(c)); }
        }
    }
    if (ROW2_Y..ROW2_Y + KEY_H).contains(&y) {
        for (i, &c) in ROW2.iter().enumerate() {
            let kx = ROW2_X + i as i32 * KEY_STEP;
            if (kx..kx + KEY_W).contains(&x) { return Some(KeyPress::Char(c)); }
        }
        if (BKSP_X..BKSP_X + BKSP_W).contains(&x) { return Some(KeyPress::Backspace); }
    }
    if (ROW3_Y..ROW3_Y + KEY_H).contains(&y) {
        if (SPACE_X..SPACE_X + SPACE_W).contains(&x) { return Some(KeyPress::Space); }
        if (BKSP_X..BKSP_X   + BKSP_W).contains(&x) { return Some(KeyPress::Backspace); }
    }
    if (PP_BTN_Y..PP_BTN_Y + PP_BTN_H).contains(&y) {
        if (PP_SKIP_X..PP_SKIP_X       + PP_BTN_W).contains(&x) { return Some(KeyPress::Skip); }
        if (PP_CONFIRM_X..PP_CONFIRM_X + PP_BTN_W).contains(&x) { return Some(KeyPress::Confirm); }
    }
    None
}
