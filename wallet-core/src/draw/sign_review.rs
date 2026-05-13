use embedded_graphics::mono_font::ascii::FONT_6X10;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::geometry::Point;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::text::{Alignment::Center, Text};

use crate::layout::{SCREEN_W, NAV_PREV_X, NAV_NEXT_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H};
use super::{draw_button, white_stroke, white_text};

pub fn draw<D>(display: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let small  = MonoTextStyle::new(&FONT_6X10, Rgb565::CSS_GRAY);
    let cx     = SCREEN_W / 2;

    Text::with_alignment("Review Transaction", Point::new(cx, 50), white_text(), Center)
        .draw(display)?;

    Text::with_alignment("Send",                              Point::new(cx, 120), small, Center).draw(display)?;
    Text::with_alignment("0.001 BTC",                        Point::new(cx, 155), white_text(), Center).draw(display)?;
    Text::with_alignment("To: bc1pqyqszqgp...qyqszqg",      Point::new(cx, 230), small, Center).draw(display)?;
    Text::with_alignment("Fee: 500 sats",                    Point::new(cx, 270), small, Center).draw(display)?;

    draw_button(display, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, "Cancel",  white_stroke(2), white_text())?;
    draw_button(display, NAV_NEXT_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, "Sign >",  white_stroke(2), white_text())?;

    Ok(())
}
