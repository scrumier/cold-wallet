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

pub fn draw<D>(display: &mut D, signed_b64: Option<&str>) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let small = MonoTextStyle::new(&FONT_6X10, Rgb565::CSS_GRAY);

    Text::with_alignment("Signed PSBT", Point::new(SCREEN_W / 2, 45), white_text(), Center)
        .draw(display)?;

    match signed_b64 {
        Some(b64) => draw_qr(display, b64.as_bytes())?,
        None => {
            draw_qr_placeholder(display)?;
            Text::with_alignment("Signing…", Point::new(SCREEN_W / 2, QR_Y + QR_SIZE / 2 + 7), small, Center)
                .draw(display)?;
        }
    }

    Text::with_alignment("Scan with your wallet app", Point::new(SCREEN_W / 2, QR_Y + QR_SIZE + 25), small, Center)
        .draw(display)?;

    draw_button(display, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, "< Done", white_stroke(2), white_text())?;

    Ok(())
}

// ── QR rendering ─────────────────────────────────────────────────────────────

#[cfg(feature = "std")]
fn draw_qr<D>(display: &mut D, data: &[u8]) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    use qrcode::{EcLevel, QrCode};
    use qrcode::types::Color as QrColor;

    let qr = match QrCode::with_error_correction_level(data, EcLevel::L) {
        Ok(q) => q,
        Err(_) => return draw_qr_placeholder(display),
    };

    let modules = qr.width();
    let total_modules = modules + 8;
    let module_px = (QR_SIZE as usize / total_modules).max(1);
    let px_used = total_modules * module_px;
    let border = ((QR_SIZE as usize).saturating_sub(px_used) / 2) as i32;
    let quiet_px = (4 * module_px) as i32;
    let origin_x = QR_X + border + quiet_px;
    let origin_y = QR_Y + border + quiet_px;

    let fill_white = PrimitiveStyleBuilder::new().fill_color(Rgb565::WHITE).build();
    let fill_black = PrimitiveStyleBuilder::new().fill_color(Rgb565::BLACK).build();

    Rectangle::new(Point::new(QR_X, QR_Y), Size::new(QR_SIZE as u32, QR_SIZE as u32))
        .into_styled(fill_white)
        .draw(display)?;

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
fn draw_qr<D>(display: &mut D, _data: &[u8]) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    draw_qr_placeholder(display)
}

fn draw_qr_placeholder<D>(display: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    Rectangle::new(Point::new(QR_X, QR_Y), Size::new(QR_SIZE as u32, QR_SIZE as u32))
        .into_styled(white_stroke(2))
        .draw(display)?;
    Ok(())
}
