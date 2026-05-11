use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;

use crate::layout::{HOME_X0, HOME_X1, HOME_Y0, HOME_Y1, HOME_BTN_W, HOME_BTN_H};
use super::{draw_button, white_stroke, white_text};

pub fn draw<D>(display: &mut D) -> Result<(), D::Error>
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
