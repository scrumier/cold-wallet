use embedded_graphics::mono_font::ascii::FONT_6X10;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::geometry::Point;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::text::{Alignment::Center, Text};

use crate::layout::{SCREEN_W, QR_X, QR_Y, QR_SIZE, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H};
use super::{draw_button, white_stroke, white_text};

pub fn draw<D>(display: &mut D, address: Option<&str>) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let small = MonoTextStyle::new(&FONT_6X10, Rgb565::CSS_GRAY);

    Text::with_alignment("Receive", Point::new(SCREEN_W / 2, 35), white_text(), Center)
        .draw(display)?;

    match address {
        Some(addr) => {
            // bc1p/tb1p address is 62 chars — display as two 31-char lines.
            let (line1, line2) = addr.split_at(31);
            Text::with_alignment(line1, Point::new(SCREEN_W / 2, 65), small, Center)
                .draw(display)?;
            Text::with_alignment(line2, Point::new(SCREEN_W / 2, 80), small, Center)
                .draw(display)?;

            draw_qr(display, addr)?;
        }
        None => {
            Text::with_alignment(
                "Generating address\u{2026}",
                Point::new(SCREEN_W / 2, 72),
                small,
                Center,
            )
            .draw(display)?;

            super::draw_qr_placeholder(display, QR_X, QR_Y, QR_SIZE)?;
        }
    }

    draw_button(display, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, "< Back", white_stroke(2), white_text())?;

    Ok(())
}

// ── QR rendering ─────────────────────────────────────────────────────────────

/// Uppercases for QR alphanumeric mode (more efficient than byte mode, and
/// standard practice — verifying software lowercases before validation),
/// then delegates to the shared renderer.
fn draw_qr<D>(display: &mut D, address: &str) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let (upper, len) = upper_address(address.as_bytes());
    super::draw_qr_data(display, &upper[..len], QR_X, QR_Y, QR_SIZE)
}

/// Copies `data` into a fixed buffer, uppercasing ASCII. Returns the buffer and
/// the number of valid bytes. Split out from `draw_qr` so the transformation
/// itself is testable without a draw target.
fn upper_address(data: &[u8]) -> ([u8; 62], usize) {
    let mut upper = [0u8; 62];
    let len = data.len().min(upper.len());
    for (i, &b) in data[..len].iter().enumerate() {
        upper[i] = b.to_ascii_uppercase();
    }
    (upper, len)
}

#[cfg(test)]
mod tests {
    use super::upper_address;

    #[test]
    fn upper_address_uppercases_and_truncates() {
        let (buf, len) = upper_address(b"bc1pABCdef");
        assert_eq!(len, 10);
        assert_eq!(&buf[..len], b"BC1PABCDEF");

        // A 62-char bc1p address is the maximum; anything longer is clamped.
        let (buf, len) = upper_address(&[b'a'; 80]);
        assert_eq!(len, 62);
        assert_eq!(buf[0], b'A');
    }
}
