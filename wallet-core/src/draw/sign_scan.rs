use embedded_graphics::mono_font::ascii::FONT_6X10;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::geometry::Point;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::primitives::Rectangle;
use embedded_graphics::text::{Alignment::Center, Text};

use crate::layout::{SCREEN_W, SIGN_VF_X, SIGN_VF_Y, SIGN_VF_W, SIGN_VF_H,
                    SD_FILE_X, SD_FILE_W, SD_FILE_H, SD_FILES_MAX,
                    NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H};
use super::{draw_button, white_stroke, white_text};

/// Renders the PSBT loading screen. With the microSD exchange (roadmap
/// decision), "scanning" is now selecting a `*.psbt` file dropped by the
/// host. The simulator taps the rows; the hardware crate taps the same
/// coordinates.
pub fn draw<D>(display: &mut D, sd_files: &[&str], scan_error: bool) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let small  = MonoTextStyle::new(&FONT_6X10, Rgb565::CSS_GRAY);
    let mono   = MonoTextStyle::new(&FONT_6X10, Rgb565::WHITE);
    let yellow = MonoTextStyle::new(&FONT_6X10, Rgb565::CSS_YELLOW);

    Text::with_alignment("Load PSBT (microSD)", Point::new(SCREEN_W / 2, 45), white_text(), Center)
        .draw(display)?;

    Rectangle::new(Point::new(SIGN_VF_X, SIGN_VF_Y), Size::new(SIGN_VF_W as u32, SIGN_VF_H as u32))
        .into_styled(white_stroke(2))
        .draw(display)?;

    if sd_files.is_empty() {
        Text::with_alignment(
            "No *.psbt file in the SD folder",
            Point::new(SCREEN_W / 2, SIGN_VF_Y + SIGN_VF_H / 2 - 4),
            small,
            Center,
        ).draw(display)?;
        Text::with_alignment(
            "Export one from Sparrow, then return here",
            Point::new(SCREEN_W / 2, SIGN_VF_Y + SIGN_VF_H / 2 + 16),
            small,
            Center,
        ).draw(display)?;
    } else {
        for (i, name) in sd_files.iter().take(SD_FILES_MAX).enumerate() {
            let row_y = crate::layout::sd_file_y(i);
            // Truncate long names to the row width (6 px per char).
            let max_chars = (SD_FILE_W - 24) as usize / 6;
            let shown = if name.len() > max_chars { &name[..max_chars] } else { name };
            Text::with_alignment(shown, Point::new(SD_FILE_X + 12, row_y + SD_FILE_H / 2 + 4), mono, Center)
                .draw(display)?;
        }
    }

    // Feedback when the last loaded file was rejected (bad base64 / invalid PSBT).
    if scan_error {
        Text::with_alignment(
            "PSBT rejected — check the file and retry",
            Point::new(SCREEN_W / 2, SIGN_VF_Y + SIGN_VF_H + 25),
            yellow,
            Center,
        ).draw(display)?;
    }

    draw_button(display, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, "Cancel", white_stroke(2), white_text())?;

    Ok(())
}
