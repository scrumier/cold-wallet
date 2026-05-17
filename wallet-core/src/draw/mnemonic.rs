use embedded_graphics::mono_font::ascii::FONT_6X10;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::geometry::Point;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::primitives::{PrimitiveStyleBuilder, Rectangle};
use embedded_graphics::text::{Alignment::Center, Text};

use crate::layout::{SCREEN_W, NAV_PREV_X, NAV_NEXT_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H};
use super::{draw_button, white_stroke, dim_stroke, white_text, dim_text, fmt_u8};

pub fn draw<D>(display: &mut D, page: u8, words: &[&'static str; 24]) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let btn_s = white_stroke(2);
    let dim_s = dim_stroke();
    let btn_t = white_text();
    let dim_t = dim_text();
    let num_t = MonoTextStyle::new(&FONT_6X10, Rgb565::new(20, 40, 20));

    let page_labels = ["Page 1 / 4", "Page 2 / 4", "Page 3 / 4", "Page 4 / 4"];
    let page_label = page_labels.get(page as usize).copied().unwrap_or("Page ? / 4");
    Text::with_alignment(page_label, Point::new(SCREEN_W / 2, 30), num_t, Center)
        .draw(display)?;

    let start = (page as usize).min(3) * 6;
    for i in 0..6 {
        let idx   = start + i;
        let row_y = 60 + (i as i32) * 58;

        let mut num_buf = [0u8; 4];
        let word = words.get(idx).copied().unwrap_or("—");
        Text::new(fmt_u8(idx as u8 + 1, &mut num_buf), Point::new(80, row_y + 15), num_t)
            .draw(display)?;
        Text::new(word, Point::new(120, row_y + 15), white_text()).draw(display)?;

        Rectangle::new(Point::new(80, row_y + 40), Size::new(640, 1))
            .into_styled(PrimitiveStyleBuilder::new().fill_color(Rgb565::new(6, 12, 6)).build())
            .draw(display)?;
    }

    if page > 0 {
        draw_button(display, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, "< Prev", btn_s, btn_t)?;
    } else {
        draw_button(display, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, "< Prev", dim_s, dim_t)?;
    }

    let next_label = if page == 3 { "Done >" } else { "Next >" };
    draw_button(display, NAV_NEXT_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, next_label, btn_s, btn_t)?;

    Ok(())
}
