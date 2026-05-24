use embedded_graphics::mono_font::ascii::{FONT_6X10, FONT_10X20};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::geometry::Point;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::primitives::{PrimitiveStyleBuilder, Rectangle};
use embedded_graphics::text::{Alignment::Center, Text};

use crate::layout::*;
use crate::state::pin_key_pos;
use super::{draw_button, white_stroke, white_text, dim_text};

pub fn draw<D>(display: &mut D, order: &[u8; 10], len: u8, confirm: bool) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let btn_t = white_text();
    let small = MonoTextStyle::new(&FONT_6X10, Rgb565::new(20, 40, 20));

    let label = if confirm { "Confirm your PIN" } else { "Choose a PIN" };
    Text::with_alignment(label, Point::new(SCREEN_W / 2, 40), small, Center).draw(display)?;

    for i in 0..6i32 {
        let dx    = DOTS_X + i * (DOT_SIZE + DOT_GAP);
        let style = if i < len as i32 {
            PrimitiveStyleBuilder::new().fill_color(Rgb565::WHITE).build()
        } else {
            white_stroke(1)
        };
        Rectangle::new(Point::new(dx, DOTS_Y), Size::new(DOT_SIZE as u32, DOT_SIZE as u32))
            .into_styled(style)
            .draw(display)?;
    }

    let mut digit_buf = [0u8; 1];
    for (pos, &digit) in order.iter().enumerate() {
        let (kx, ky) = pin_key_pos(pos);
        Rectangle::new(Point::new(kx, ky), Size::new(PIN_KEY_W as u32, PIN_KEY_H as u32))
            .into_styled(white_stroke(2))
            .draw(display)?;

        digit_buf[0] = b'0' + digit;
        let s = core::str::from_utf8(&digit_buf).unwrap_or("?");
        Text::with_alignment(s, Point::new(kx + PIN_KEY_W / 2, ky + PIN_KEY_H / 2 + 7), btn_t, Center)
            .draw(display)?;
    }

    if len > 0 {
        draw_button(display, PIN_DEL_X, PIN_DEL_Y, PIN_DEL_W, PIN_DEL_H, "<- Del", white_stroke(2), btn_t)?;
    }

    Ok(())
}

pub fn draw_mismatch<D>(display: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let red   = MonoTextStyle::new(&FONT_10X20, Rgb565::RED);
    let small = MonoTextStyle::new(&FONT_6X10, Rgb565::new(20, 40, 20));

    Text::with_alignment("Wrong PIN", Point::new(SCREEN_W / 2, SCREEN_H / 2 - 20), red, Center)
        .draw(display)?;
    Text::with_alignment("Tap anywhere to retry", Point::new(SCREEN_W / 2, SCREEN_H / 2 + 20), small, Center)
        .draw(display)?;

    Ok(())
}

/// Drawn while the PIN-derived key is being computed (≈500ms release / 2-3s
/// debug). Without this feedback the screen looks frozen.
pub fn draw_verifying<D>(display: &mut D, label: &str) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let big   = white_text();
    let small = MonoTextStyle::new(&FONT_6X10, Rgb565::CSS_GRAY);

    Text::with_alignment(label, Point::new(SCREEN_W / 2, SCREEN_H / 2 - 10), big, Center)
        .draw(display)?;
    Text::with_alignment(
        "deriving encryption key — please wait",
        Point::new(SCREEN_W / 2, SCREEN_H / 2 + 25),
        small, Center,
    )
    .draw(display)?;
    Ok(())
}

pub fn draw_locked<D>(display: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let red   = MonoTextStyle::new(&FONT_10X20, Rgb565::RED);
    let small = MonoTextStyle::new(&FONT_6X10, Rgb565::new(20, 40, 20));

    Text::with_alignment("Device locked", Point::new(SCREEN_W / 2, SCREEN_H / 2 - 40), red, Center)
        .draw(display)?;
    Text::with_alignment(
        "Too many wrong PIN attempts.",
        Point::new(SCREEN_W / 2, SCREEN_H / 2),
        dim_text(),
        Center,
    )
    .draw(display)?;
    Text::with_alignment(
        "Restart the device to try again.",
        Point::new(SCREEN_W / 2, SCREEN_H / 2 + 30),
        small,
        Center,
    )
    .draw(display)?;

    Ok(())
}
