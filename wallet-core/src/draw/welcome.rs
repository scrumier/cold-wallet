use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;

use crate::layout::{BTN_X, BTN_W, BTN_H, BTN_NEW_Y, BTN_RESTORE_Y};
use super::{draw_button, white_stroke, white_text};

pub fn draw<D>(display: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let s = white_stroke(2);
    let t = white_text();

    draw_button(display, BTN_X, BTN_NEW_Y,     BTN_W, BTN_H, "New Wallet",     s, t)?;
    draw_button(display, BTN_X, BTN_RESTORE_Y, BTN_W, BTN_H, "Restore Wallet", s, t)?;

    Ok(())
}
