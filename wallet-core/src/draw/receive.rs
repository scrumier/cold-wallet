use embedded_graphics::mono_font::ascii::FONT_6X10;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::geometry::Point;
use embedded_graphics::mono_font::MonoTextStyle;
#[cfg(feature = "std")]
use embedded_graphics::primitives::PrimitiveStyleBuilder;
use embedded_graphics::primitives::Rectangle;
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
            // bc1p address is 62 chars — display as two 31-char lines.
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

            draw_qr_placeholder(display)?;
        }
    }

    draw_button(display, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, "< Back", white_stroke(2), white_text())?;

    Ok(())
}

// ── QR rendering ─────────────────────────────────────────────────────────────

#[cfg(feature = "std")]
fn draw_qr<D>(display: &mut D, address: &str) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    use qrcode::{EcLevel, QrCode};
    use qrcode::types::Color as QrColor;

    // Uppercase for QR alphanumeric mode: more efficient than byte mode,
    // and standard practice — verifying software lowercases before validation.
    let mut upper = [0u8; 62];
    let bytes = address.as_bytes();
    let len = bytes.len().min(upper.len());
    for (i, &b) in bytes[..len].iter().enumerate() {
        upper[i] = b.to_ascii_uppercase();
    }

    let qr = match QrCode::with_error_correction_level(&upper[..len], EcLevel::M) {
        Ok(q) => q,
        Err(_) => return draw_qr_placeholder(display),
    };

    let modules = qr.width();

    // Scale to fit QR_SIZE pixels with a 4-module quiet zone on each side.
    let total_modules = modules + 8; // 4 quiet-zone modules per side
    let module_px = (QR_SIZE as usize / total_modules).max(1);
    let px_used = total_modules * module_px;
    let border = ((QR_SIZE as usize).saturating_sub(px_used) / 2) as i32;
    let quiet_px = (4 * module_px) as i32;
    let origin_x = QR_X + border + quiet_px;
    let origin_y = QR_Y + border + quiet_px;

    let fill_white = PrimitiveStyleBuilder::new().fill_color(Rgb565::WHITE).build();
    let fill_black = PrimitiveStyleBuilder::new().fill_color(Rgb565::BLACK).build();

    // White background including quiet zone.
    Rectangle::new(Point::new(QR_X, QR_Y), Size::new(QR_SIZE as u32, QR_SIZE as u32))
        .into_styled(fill_white)
        .draw(display)?;

    // Dark modules — qr[(col, row)] per the qrcode crate's Index impl.
    let mpx = module_px as u32;
    for row in 0..modules {
        for col in 0..modules {
            if qr[(col, row)] == QrColor::Dark {
                let px = origin_x + (col * module_px) as i32;
                let py = origin_y + (row * module_px) as i32;
                Rectangle::new(Point::new(px, py), Size::new(mpx, mpx))
                    .into_styled(fill_black)
                    .draw(display)?;
            }
        }
    }

    Ok(())
}

#[cfg(not(feature = "std"))]
fn draw_qr<D>(display: &mut D, _address: &str) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    draw_qr_placeholder(display)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    #[test]
    fn qr_encodes_bc1p_address() {
        use qrcode::{EcLevel, QrCode};
        // A bc1p address is always 62 chars (4 prefix + 58 bech32m data chars).
        let addr = "bc1pqpzry9x8gf2tvdw0s3jn54khce6mua7lqpzry9x8gf2tvdw0s3jn54khce";
        assert_eq!(addr.len(), 62, "test address must be exactly 62 chars");

        let mut upper = [0u8; 62];
        let bytes = addr.as_bytes();
        let len = bytes.len().min(upper.len());
        for (i, &b) in bytes[..len].iter().enumerate() {
            upper[i] = b.to_ascii_uppercase();
        }
        let qr = QrCode::with_error_correction_level(&upper[..len], EcLevel::M)
            .expect("QR encoding failed for bc1p address");
        // 62 uppercase alphanumeric chars with EcLevel::M → Version 4 (33×33 modules).
        assert_eq!(qr.width(), 33, "unexpected QR version for a 62-char bc1p address");
    }
}

fn draw_qr_placeholder<D>(display: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    Rectangle::new(Point::new(QR_X, QR_Y), Size::new(QR_SIZE as u32, QR_SIZE as u32))
        .into_styled(white_stroke(2))
        .draw(display)?;

    Text::with_alignment(
        "QR",
        Point::new(SCREEN_W / 2, QR_Y + QR_SIZE / 2 + 7),
        white_text(),
        Center,
    )
    .draw(display)?;

    Ok(())
}
