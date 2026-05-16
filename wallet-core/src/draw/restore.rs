use embedded_graphics::mono_font::ascii::FONT_6X10;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::geometry::Point;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::primitives::Rectangle;
use embedded_graphics::text::Text;

use crate::layout::{
    SCREEN_W,
    RESTORE_PROGRESS_Y, RESTORE_INPUT_Y,
    RESTORE_SUGGEST_Y, RESTORE_SUGGEST_H, RESTORE_SUGGEST_W,
    RESTORE_SUGGEST_X0, RESTORE_SUGGEST_X1, RESTORE_SUGGEST_X2,
    PP_SKIP_X, PP_BTN_Y, PP_BTN_W, PP_BTN_H,
};
use crate::state::find_matches;
use super::{draw_button, white_stroke, white_text, dim_stroke, dim_text, fmt_u8};
use super::passphrase::draw_keyboard;

pub fn draw<D>(
    display: &mut D,
    word_idx: u8,
    buf: &[u8; 8],
    buf_len: u8,
    error: bool,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let small  = MonoTextStyle::new(&FONT_6X10, Rgb565::CSS_GRAY);
    let hi     = MonoTextStyle::new(&FONT_6X10, Rgb565::WHITE);
    let red    = MonoTextStyle::new(&FONT_6X10, Rgb565::RED);

    // ── Progress line ─────────────────────────────────────────────────────────
    {
        let mut idx_buf  = [0u8; 4];
        let mut tot_buf  = [0u8; 4];
        let prefix = "Word ";
        let idx_s  = fmt_u8(word_idx + 1, &mut idx_buf);
        let tot_s  = fmt_u8(24, &mut tot_buf);

        // Build "Word X / 24" by drawing the parts separately.
        let cx = SCREEN_W / 2;
        // Approximate: each char = 6px, total "Word 1 / 24" ≈ 11 chars = 66px
        let x_prefix = cx - 33;
        Text::new(prefix, Point::new(x_prefix, RESTORE_PROGRESS_Y), small).draw(display)?;
        let x_idx = x_prefix + 6 * prefix.len() as i32;
        Text::new(idx_s,  Point::new(x_idx,            RESTORE_PROGRESS_Y), hi).draw(display)?;
        let x_sep = x_idx + 6 * idx_s.len() as i32;
        Text::new(" / ", Point::new(x_sep,              RESTORE_PROGRESS_Y), small).draw(display)?;
        Text::new(tot_s,  Point::new(x_sep + 6 * 3,    RESTORE_PROGRESS_Y), small).draw(display)?;
    }

    // ── Error banner ──────────────────────────────────────────────────────────
    if error {
        Text::new(
            "Invalid mnemonic - please re-enter all 24 words",
            Point::new(SCREEN_W / 2 - 150, RESTORE_PROGRESS_Y + 16),
            red,
        ).draw(display)?;
    }

    // ── Typed prefix + cursor ─────────────────────────────────────────────────
    let typed = core::str::from_utf8(&buf[..buf_len as usize]).unwrap_or("");
    {
        // Input bar: just show typed chars left-aligned + blinking cursor hint
        let input_x = SCREEN_W / 2 - 100;
        Text::new(typed, Point::new(input_x, RESTORE_INPUT_Y), white_text()).draw(display)?;
        // Cursor block
        let cursor_x = input_x + 10 * buf_len as i32;
        Rectangle::new(
            Point::new(cursor_x, RESTORE_INPUT_Y - 12),
            Size::new(8, 14),
        )
        .into_styled(white_stroke(1))
        .draw(display)?;
    }

    // ── Autocomplete suggestions ──────────────────────────────────────────────
    let suggestions = find_matches(buf, buf_len);
    let word_list   = bip39::Language::English.word_list();
    let xs = [RESTORE_SUGGEST_X0, RESTORE_SUGGEST_X1, RESTORE_SUGGEST_X2];
    for (i, &sx) in xs.iter().enumerate() {
        if let Some(idx) = suggestions[i] {
            let word = word_list[idx as usize];
            draw_button(
                display, sx, RESTORE_SUGGEST_Y, RESTORE_SUGGEST_W, RESTORE_SUGGEST_H,
                word, white_stroke(1), hi,
            )?;
        } else {
            // Empty slot — draw a dim rectangle so the user sees the tap area
            Rectangle::new(
                Point::new(sx, RESTORE_SUGGEST_Y),
                Size::new(RESTORE_SUGGEST_W as u32, RESTORE_SUGGEST_H as u32),
            )
            .into_styled(dim_stroke())
            .draw(display)?;
        }
    }

    // ── QWERTY keyboard ───────────────────────────────────────────────────────
    draw_keyboard(display)?;

    // ── Cancel button ─────────────────────────────────────────────────────────
    draw_button(
        display,
        PP_SKIP_X, PP_BTN_Y, PP_BTN_W, PP_BTN_H,
        "Cancel", dim_stroke(), dim_text(),
    )?;

    Ok(())
}
