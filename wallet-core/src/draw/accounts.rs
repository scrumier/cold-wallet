use embedded_graphics::mono_font::ascii::FONT_6X10;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::geometry::Point;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::text::{Alignment::Center, Text};

use crate::layout::{SCREEN_W, SCREEN_H, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H};
use super::{draw_button, white_stroke, white_text};

pub fn draw<D>(display: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let small = MonoTextStyle::new(&FONT_6X10, Rgb565::CSS_GRAY);

    Text::with_alignment("Accounts", Point::new(SCREEN_W / 2, 65), white_text(), Center)
        .draw(display)?;

    Text::with_alignment("Account 1  ·  m/86'/0'/0'",
        Point::new(SCREEN_W / 2, SCREEN_H / 2), small, Center)
        .draw(display)?;

    draw_button(display, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, "< Back", white_stroke(2), white_text())?;

    Ok(())
}
