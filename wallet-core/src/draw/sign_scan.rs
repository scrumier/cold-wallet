use embedded_graphics::mono_font::ascii::FONT_6X10;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::geometry::Point;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::primitives::Rectangle;
use embedded_graphics::text::{Alignment::Center, Text};

use crate::layout::{SCREEN_W, SIGN_VF_X, SIGN_VF_Y, SIGN_VF_W, SIGN_VF_H,
                    NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H};
use super::{draw_button, white_stroke, white_text};

pub fn draw<D>(display: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let small = MonoTextStyle::new(&FONT_6X10, Rgb565::CSS_GRAY);

    Text::with_alignment("Scan PSBT QR", Point::new(SCREEN_W / 2, 45), white_text(), Center)
        .draw(display)?;

    Rectangle::new(Point::new(SIGN_VF_X, SIGN_VF_Y), Size::new(SIGN_VF_W as u32, SIGN_VF_H as u32))
        .into_styled(white_stroke(2))
        .draw(display)?;

    Text::with_alignment("[tap to simulate scan]",
        Point::new(SCREEN_W / 2, SIGN_VF_Y + SIGN_VF_H / 2 + 7), small, Center)
        .draw(display)?;

    draw_button(display, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, "Cancel", white_stroke(2), white_text())?;

    Ok(())
}
