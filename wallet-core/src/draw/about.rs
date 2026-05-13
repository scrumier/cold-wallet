use embedded_graphics::mono_font::ascii::FONT_6X10;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::geometry::Point;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::text::{Alignment::Center, Text};

use crate::layout::{SCREEN_W, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H};
use super::{draw_button, white_stroke, white_text};

pub fn draw<D>(display: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let small = MonoTextStyle::new(&FONT_6X10, Rgb565::CSS_GRAY);
    let cx    = SCREEN_W / 2;

    Text::with_alignment("Cold Wallet",           Point::new(cx, 150), white_text(), Center).draw(display)?;
    Text::with_alignment("v0.1 — Bitcoin Only",   Point::new(cx, 195), small,        Center).draw(display)?;
    Text::with_alignment("BIP39 / BIP32 / BIP86", Point::new(cx, 225), small,        Center).draw(display)?;
    Text::with_alignment("Air-gapped · QR only",  Point::new(cx, 255), small,        Center).draw(display)?;

    draw_button(display, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, "< Back", white_stroke(2), white_text())?;

    Ok(())
}
