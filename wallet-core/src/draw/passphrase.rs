use embedded_graphics::mono_font::ascii::FONT_6X10;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::geometry::Point;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::primitives::Rectangle;
use embedded_graphics::text::{Alignment::Center, Text};

use crate::keyboard::{ROW0, ROW1, ROW2};
use crate::layout::*;
use super::{draw_button, white_stroke, dim_stroke, white_text, dim_text};

pub fn draw<D>(display: &mut D, buf: &[u8; 32], len: u8) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let btn_s = white_stroke(2);
    let key_s = white_stroke(1);
    let dim_s = dim_stroke();
    let btn_t = white_text();
    let dim_t = dim_text();
    let small = MonoTextStyle::new(&FONT_6X10, Rgb565::new(20, 40, 20));

    Text::with_alignment("Passphrase (optional)", Point::new(SCREEN_W / 2, 18), small, Center)
        .draw(display)?;

    Rectangle::new(Point::new(40, 28), Size::new(720, 50))
        .into_styled(white_stroke(1))
        .draw(display)?;

    let s = core::str::from_utf8(&buf[..len as usize]).unwrap_or("");
    Text::new(s, Point::new(50, 63), white_text()).draw(display)?;

    draw_key_row(display, ROW0, ROW0_X, ROW0_Y, key_s, btn_t)?;
    draw_key_row(display, ROW1, ROW1_X, ROW1_Y, key_s, btn_t)?;
    draw_key_row(display, ROW2, ROW2_X, ROW2_Y, key_s, btn_t)?;

    draw_button(display, SPACE_X, ROW3_Y, SPACE_W, KEY_H, "SPACE", btn_s, btn_t)?;
    draw_button(display, BKSP_X,  ROW3_Y, BKSP_W,  KEY_H, "<-",    btn_s, btn_t)?;

    draw_button(display, PP_SKIP_X, PP_BTN_Y, PP_BTN_W, PP_BTN_H, "Skip", btn_s, btn_t)?;

    if len > 0 {
        draw_button(display, PP_CONFIRM_X, PP_BTN_Y, PP_BTN_W, PP_BTN_H, "Confirm", btn_s, btn_t)?;
    } else {
        draw_button(display, PP_CONFIRM_X, PP_BTN_Y, PP_BTN_W, PP_BTN_H, "Confirm", dim_s, dim_t)?;
    }

    Ok(())
}

fn draw_key_row<D>(
    display: &mut D,
    keys: &[u8],
    x_start: i32,
    y: i32,
    rect_style: embedded_graphics::primitives::PrimitiveStyle<Rgb565>,
    text_style: MonoTextStyle<Rgb565>,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let mut label = [0u8; 1];
    for (i, &c) in keys.iter().enumerate() {
        let kx = x_start + i as i32 * KEY_STEP;
        Rectangle::new(Point::new(kx, y), Size::new(KEY_W as u32, KEY_H as u32))
            .into_styled(rect_style)
            .draw(display)?;
        label[0] = c;
        let s = core::str::from_utf8(&label).unwrap_or("?");
        Text::with_alignment(s, Point::new(kx + KEY_W / 2, y + KEY_H / 2 + 7), text_style, Center)
            .draw(display)?;
    }
    Ok(())
}
