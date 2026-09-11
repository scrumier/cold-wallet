mod about;
mod accounts;
mod descriptor;
mod home;
mod mnemonic;
mod passphrase;
mod pin;
mod receive;
mod restore;
mod settings;
mod sign_review;
mod sign_result;
mod sign_scan;
mod welcome;

use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::geometry::Point;
use embedded_graphics::mono_font::{ascii::FONT_10X20, MonoTextStyle};
use embedded_graphics::primitives::{PrimitiveStyle, PrimitiveStyleBuilder, Rectangle};
use embedded_graphics::text::{Alignment::Center, Text};

use crate::psbt::ParsedPsbt;
use crate::state::AppState;

#[allow(clippy::too_many_arguments)]
pub fn draw_ui<D>(
    display: &mut D,
    state: AppState,
    words: &[&'static str; 24],
    address: Option<&str>,
    psbt: Option<&ParsedPsbt>,
    signed_b64: Option<&str>,
    descriptor: Option<&str>,
    own_output_keys: Option<&[[u8; 32]]>,
    sd_files: &[&str],
    scan_error: bool,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    display.clear(Rgb565::BLACK)?;

    match state {
        AppState::Welcome                          => welcome::draw(display)?,
        AppState::NewWallet { page }               => mnemonic::draw(display, page, words)?,
        AppState::EnterPassphrase { buf, len }     => passphrase::draw(display, &buf, len)?,
        AppState::SetPin { order, len, .. }        => pin::draw(display, &order, len, false)?,
        AppState::ConfirmPin { order, len, .. }    => pin::draw(display, &order, len, true)?,
        AppState::PinMismatch                      => pin::draw_mismatch(display)?,
        AppState::PinLocked                        => pin::draw_locked(display)?,
        AppState::PinVerifying { .. }              => pin::draw_verifying(display, "Verifying PIN…")?,
        AppState::PinConfirming { .. }             => pin::draw_verifying(display, "Saving wallet…")?,
        AppState::EnterPin { order, len, .. }      => pin::draw(display, &order, len, false)?,
        AppState::RestoreWallet { word_idx, buf, buf_len, error, .. }
                                                   => restore::draw(display, word_idx, &buf, buf_len, error)?,
        AppState::Home                             => home::draw(display)?,
        AppState::Receive                          => receive::draw(display, address)?,
        AppState::Accounts                         => accounts::draw(display)?,
        AppState::Settings                         => settings::draw(display)?,
        AppState::Descriptor                       => descriptor::draw(display, descriptor)?,
        AppState::ShowMnemonic { page }            => mnemonic::draw(display, page, words)?,
        AppState::About                            => about::draw(display)?,
        AppState::SignScan                         => sign_scan::draw(display, sd_files, scan_error)?,
        AppState::SignReview                       => sign_review::draw(display, psbt, own_output_keys)?,
        AppState::SignResult                       => sign_result::draw(display, signed_b64)?,
    }

    Ok(())
}

// Shared helpers — pub(crate) so screen modules can use them

#[allow(clippy::too_many_arguments)]
pub(crate) fn draw_button<D>(
    display: &mut D,
    x: i32, y: i32, w: i32, h: i32,
    label: &str,
    rect_style: PrimitiveStyle<Rgb565>,
    text_style: MonoTextStyle<Rgb565>,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    Rectangle::new(Point::new(x, y), Size::new(w as u32, h as u32))
        .into_styled(rect_style)
        .draw(display)?;

    Text::with_alignment(label, Point::new(x + w / 2, y + h / 2 + 7), text_style, Center)
        .draw(display)?;

    Ok(())
}

pub(crate) fn white_stroke(width: u32) -> PrimitiveStyle<Rgb565> {
    PrimitiveStyleBuilder::new().stroke_color(Rgb565::WHITE).stroke_width(width).build()
}

pub(crate) fn dim_stroke() -> PrimitiveStyle<Rgb565> {
    PrimitiveStyleBuilder::new().stroke_color(Rgb565::new(10, 20, 10)).stroke_width(2).build()
}

pub(crate) fn white_text() -> MonoTextStyle<'static, Rgb565> {
    MonoTextStyle::new(&FONT_10X20, Rgb565::WHITE)
}

pub(crate) fn dim_text() -> MonoTextStyle<'static, Rgb565> {
    MonoTextStyle::new(&FONT_10X20, Rgb565::new(10, 20, 10))
}

pub(crate) fn fmt_u8(n: u8, buf: &mut [u8; 4]) -> &str {
    let mut pos = 4usize;
    let mut val = n;
    loop {
        pos -= 1;
        buf[pos] = b'0' + (val % 10);
        val /= 10;
        if val == 0 { break; }
    }
    core::str::from_utf8(&buf[pos..]).unwrap_or("?")
}

#[cfg(test)]
mod tests {
    use super::fmt_u8;

    #[test]
    fn formats_numbers() {
        let mut buf = [0u8; 4];
        assert_eq!(fmt_u8(0, &mut buf), "0");
        assert_eq!(fmt_u8(7, &mut buf), "7");
        assert_eq!(fmt_u8(42, &mut buf), "42");
        assert_eq!(fmt_u8(255, &mut buf), "255");
    }
}

// ── QR rendering (generation only — the qrcode crate needs std) ──────────────
// On the bare-metal target these fall back to a placeholder until phase 4
// of the roadmap (a no_std encoder).

#[cfg(feature = "std")]
pub(crate) fn draw_qr_data<D>(
    display: &mut D,
    data: &[u8],
    x: i32,
    y: i32,
    size: i32,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    use qrcode::types::Color as QrColor;
    use qrcode::{EcLevel, QrCode};

    let qr = match QrCode::with_error_correction_level(data, EcLevel::L) {
        Ok(q) => q,
        Err(_) => return draw_qr_placeholder(display, x, y, size),
    };

    let modules = qr.width();

    // Scale to fit `size` px with a 4-module quiet zone on each side.
    let total_modules = modules + 8;
    let module_px = ((size as usize) / total_modules).max(1);
    let px_used = total_modules * module_px;
    let border = ((size as usize).saturating_sub(px_used) / 2) as i32;
    let quiet_px = (4 * module_px) as i32;
    let origin_x = x + border + quiet_px;
    let origin_y = y + border + quiet_px;

    let fill_white = PrimitiveStyleBuilder::new().fill_color(Rgb565::WHITE).build();
    let fill_black = PrimitiveStyleBuilder::new().fill_color(Rgb565::BLACK).build();

    Rectangle::new(Point::new(x, y), Size::new(size as u32, size as u32))
        .into_styled(fill_white)
        .draw(display)?;

    // Dark modules — qr[(col, row)] per the qrcode crate's Index impl.
    let mpx = module_px as u32;
    for row in 0..modules {
        for col in 0..modules {
            if qr[(col, row)] == QrColor::Dark {
                Rectangle::new(
                    Point::new(
                        origin_x + (col * module_px) as i32,
                        origin_y + (row * module_px) as i32,
                    ),
                    Size::new(mpx, mpx),
                )
                .into_styled(fill_black)
                .draw(display)?;
            }
        }
    }

    Ok(())
}

#[cfg(not(feature = "std"))]
pub(crate) fn draw_qr_data<D>(
    display: &mut D,
    _data: &[u8],
    x: i32,
    y: i32,
    size: i32,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    draw_qr_placeholder(display, x, y, size)
}

pub(crate) fn draw_qr_placeholder<D>(
    display: &mut D,
    x: i32,
    y: i32,
    size: i32,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    Rectangle::new(Point::new(x, y), Size::new(size as u32, size as u32))
        .into_styled(white_stroke(2))
        .draw(display)?;

    Text::with_alignment("QR", Point::new(x + size / 2, y + size / 2 + 7), white_text(), Center)
        .draw(display)?;

    Ok(())
}
