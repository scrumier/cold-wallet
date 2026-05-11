mod home;
mod mnemonic;
mod passphrase;
mod pin;
mod welcome;

use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::geometry::Point;
use embedded_graphics::mono_font::{ascii::FONT_10X20, MonoTextStyle};
use embedded_graphics::primitives::{PrimitiveStyle, PrimitiveStyleBuilder, Rectangle};
use embedded_graphics::text::{Alignment::Center, Text};

use crate::state::AppState;

pub fn draw_ui<D>(display: &mut D, state: AppState) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    display.clear(Rgb565::BLACK)?;

    match state {
        AppState::Welcome                          => welcome::draw(display)?,
        AppState::NewWallet { page }               => mnemonic::draw(display, page)?,
        AppState::EnterPassphrase { buf, len }     => passphrase::draw(display, &buf, len)?,
        AppState::SetPin { order, len, .. }        => pin::draw(display, &order, len, false)?,
        AppState::ConfirmPin { order, len, .. }    => pin::draw(display, &order, len, true)?,
        AppState::PinMismatch                      => pin::draw_mismatch(display)?,
        AppState::Home                             => home::draw(display)?,
        _                                          => draw_placeholder(display, state)?,
    }

    Ok(())
}

fn draw_placeholder<D>(display: &mut D, state: AppState) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let label = match state {
        AppState::RestoreWallet => "Restore Wallet",
        AppState::EnterPin      => "Enter PIN",
        AppState::Receive       => "Receive",
        AppState::SignScan      => "Scan QR",
        AppState::SignReview    => "Review TX",
        AppState::SignResult    => "Signed QR",
        AppState::Accounts      => "Accounts",
        AppState::Settings      => "Settings",
        AppState::ShowMnemonic  => "Show Mnemonic",
        AppState::ChangePin     => "Change PIN",
        AppState::About         => "About",
        _                       => "—",
    };

    Text::with_alignment(label, Point::new(400, 240), white_text(), Center).draw(display)?;

    Ok(())
}

// Shared helpers — pub(crate) so screen modules can use them

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
