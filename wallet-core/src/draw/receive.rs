use embedded_graphics::mono_font::ascii::FONT_6X10;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::geometry::Point;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::primitives::Rectangle;
use embedded_graphics::text::{Alignment::Center, Text};

use crate::layout::{SCREEN_W, QR_X, QR_Y, QR_SIZE, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H};
use super::{draw_button, white_stroke, white_text};

const PLACEHOLDER_ADDR: &str = "bc1pqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqg";

pub fn draw<D>(display: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let small = MonoTextStyle::new(&FONT_6X10, Rgb565::CSS_GRAY);

    Text::with_alignment("Receive", Point::new(SCREEN_W / 2, 35), white_text(), Center)
        .draw(display)?;

    Text::with_alignment(PLACEHOLDER_ADDR, Point::new(SCREEN_W / 2, 72), small, Center)
        .draw(display)?;

    Rectangle::new(Point::new(QR_X, QR_Y), Size::new(QR_SIZE as u32, QR_SIZE as u32))
        .into_styled(white_stroke(2))
        .draw(display)?;

    Text::with_alignment("QR", Point::new(SCREEN_W / 2, QR_Y + QR_SIZE / 2 + 7), white_text(), Center)
        .draw(display)?;

    draw_button(display, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, "< Back", white_stroke(2), white_text())?;

    Ok(())
}
