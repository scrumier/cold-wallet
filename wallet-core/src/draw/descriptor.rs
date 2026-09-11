use embedded_graphics::mono_font::ascii::FONT_6X10;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::geometry::Point;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::text::{Alignment::Center, Text};

use crate::layout::{SCREEN_W, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H};
use super::{draw_button, white_stroke, white_text};

/// Renders the descriptor export screen: the BIP386 `tr(...)` descriptor as
/// text (for copy/paste into Sparrow) and as a QR (for scanning from the hot
/// side). This is the missing link of the air-gap loop: without it, no
/// watch-only wallet can build PSBTs for this device.
pub fn draw<D>(display: &mut D, descriptor: Option<&str>) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let small = MonoTextStyle::new(&FONT_6X10, Rgb565::CSS_GRAY);
    let cx    = SCREEN_W / 2;

    Text::with_alignment("Export Descriptor", Point::new(cx, 30), white_text(), Center)
        .draw(display)?;

    match descriptor {
        Some(desc) => {
            let bytes = desc.as_bytes();

            // Text: wrapped at ~100 chars (FONT_6X10 is 6 px/char).
            const CHARS_PER_LINE: usize = 100;
            let mut y = 52;
            let mut i = 0usize;
            while i < bytes.len() {
                let end = (i + CHARS_PER_LINE).min(bytes.len());
                if let Ok(line) = core::str::from_utf8(&bytes[i..end]) {
                    Text::with_alignment(line, Point::new(cx, y), small, Center).draw(display)?;
                }
                y += 14;
                i = end;
            }

            // QR of the descriptor, centered below the text.
            super::draw_qr_data(display, bytes, cx - 120, 95, 240)?;
        }
        None => {
            Text::with_alignment(
                "No descriptor yet — finish wallet setup",
                Point::new(cx, 72),
                small,
                Center,
            )
            .draw(display)?;

            super::draw_qr_placeholder(display, cx - 120, 95, 240)?;
        }
    }

    draw_button(
        display,
        NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H,
        "< Back",
        white_stroke(2),
        white_text(),
    )?;

    Ok(())
}
