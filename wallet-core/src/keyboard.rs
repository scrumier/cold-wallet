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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_letter_keys() {
        assert!(matches!(passphrase_key_at(ROW0_X + 1, ROW0_Y + 1), Some(KeyPress::Char(b'Q'))));
        assert!(matches!(passphrase_key_at(ROW1_X + 1, ROW1_Y + 1), Some(KeyPress::Char(b'A'))));
        assert!(matches!(passphrase_key_at(ROW2_X + 1, ROW2_Y + 1), Some(KeyPress::Char(b'Z'))));
    }

    #[test]
    fn maps_space_and_backspace() {
        assert!(matches!(passphrase_key_at(SPACE_X + 1, ROW3_Y + 1), Some(KeyPress::Space)));
        assert!(matches!(
            passphrase_key_at(BKSP_X + BKSP_W - 1, ROW2_Y + 1),
            Some(KeyPress::Backspace)
        ));
        assert!(matches!(passphrase_key_at(BKSP_X + 1, ROW3_Y + 1), Some(KeyPress::Backspace)));
    }

    #[test]
    fn maps_action_buttons() {
        assert!(matches!(passphrase_key_at(PP_SKIP_X + 1, PP_BTN_Y + 1), Some(KeyPress::Skip)));
        assert!(matches!(passphrase_key_at(PP_CONFIRM_X + 1, PP_BTN_Y + 1), Some(KeyPress::Confirm)));
    }

    #[test]
    fn ignores_out_of_bounds() {
        assert!(passphrase_key_at(0, 0).is_none());
    }
}
