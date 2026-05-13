use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::geometry::Point;
use embedded_graphics::text::{Alignment::Center, Text};

use crate::layout::{SCREEN_W, SETTINGS_BTN_X, SETTINGS_BTN_W, SETTINGS_BTN_H,
                    SETTINGS_Y0, SETTINGS_Y1, SETTINGS_Y2,
                    NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H};
use super::{draw_button, white_stroke, white_text};

pub fn draw<D>(display: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    Text::with_alignment("Settings", Point::new(SCREEN_W / 2, 65), white_text(), Center)
        .draw(display)?;

    draw_button(display, SETTINGS_BTN_X, SETTINGS_Y0, SETTINGS_BTN_W, SETTINGS_BTN_H, "Show Mnemonic", white_stroke(2), white_text())?;
    draw_button(display, SETTINGS_BTN_X, SETTINGS_Y1, SETTINGS_BTN_W, SETTINGS_BTN_H, "Change PIN",    white_stroke(2), white_text())?;
    draw_button(display, SETTINGS_BTN_X, SETTINGS_Y2, SETTINGS_BTN_W, SETTINGS_BTN_H, "About",         white_stroke(2), white_text())?;

    draw_button(display, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, "< Back", white_stroke(2), white_text())?;

    Ok(())
}
