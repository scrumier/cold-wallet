use embedded_graphics::mono_font::ascii::FONT_6X10;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::geometry::Point;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::text::{Alignment::Center, Text};

use crate::layout::{SCREEN_W, NAV_PREV_X, NAV_NEXT_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H};
use crate::psbt::ParsedPsbt;
use super::{draw_button, white_stroke, white_text};

pub fn draw<D>(display: &mut D, psbt: Option<&ParsedPsbt>) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let small = MonoTextStyle::new(&FONT_6X10, Rgb565::CSS_GRAY);
    let cx    = SCREEN_W / 2;

    Text::with_alignment("Review Transaction", Point::new(cx, 50), white_text(), Center)
        .draw(display)?;

    if let Some(p) = psbt {
        // Sum all output amounts (first output = recipient; last may be change).
        // We display total-out and fee = total-in − total-out.
        let total_in: u64  = (0..p.input_count).map(|i| p.inputs[i].amount_sats).sum();
        let total_out: u64 = (0..p.output_count).map(|i| p.outputs[i].amount_sats).sum();
        let fee_sats: u64  = total_in.saturating_sub(total_out);

        // Primary recipient = first output.
        let recv_sats = if p.output_count > 0 { p.outputs[0].amount_sats } else { 0 };

        // Display amounts as satoshis (no float, no alloc).
        let mut buf = [0u8; 20];
        let amount_str = fmt_sats(recv_sats, &mut buf);
        Text::with_alignment("Send",        Point::new(cx, 120), small,      Center).draw(display)?;
        Text::with_alignment(amount_str,    Point::new(cx, 155), white_text(), Center).draw(display)?;

        let mut fee_buf = [0u8; 20];
        let fee_str = fmt_fee(fee_sats, &mut fee_buf);
        Text::with_alignment(fee_str,       Point::new(cx, 270), small,      Center).draw(display)?;

        // Destination address: show first output scriptPubKey as hex, abbreviated.
        let spk = &p.outputs[0].script_pubkey[..p.outputs[0].script_len.min(34)];
        let mut hex = [0u8; 12];  // show 5 bytes = 10 hex chars + "…"
        if p.outputs[0].script_len >= 2 {
            let data = &spk[2..spk.len().min(7)]; // skip OP_1 OP_PUSHBYTES_32
            let n = data.len().min(5);
            for (i, &b) in data[..n].iter().enumerate() {
                hex[i * 2]     = HEX[(b >> 4) as usize];
                hex[i * 2 + 1] = HEX[(b & 0xf) as usize];
            }
            hex[n * 2] = b'.';
        }
        let dest = core::str::from_utf8(&hex[..11.min(hex.len())]).unwrap_or("?");
        let mut to_buf = [0u8; 18];
        let to_str = fmt_to(dest, &mut to_buf);
        Text::with_alignment(to_str,        Point::new(cx, 215), small,      Center).draw(display)?;
    } else {
        Text::with_alignment("Loading…", Point::new(cx, 200), small, Center).draw(display)?;
    }

    draw_button(display, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, "Cancel",  white_stroke(2), white_text())?;
    draw_button(display, NAV_NEXT_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, "Sign >",  white_stroke(2), white_text())?;

    Ok(())
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Format satoshis as "NNN sats" or "N.NNNNNNN BTC" — no alloc, stack only.
fn fmt_sats(sats: u64, buf: &mut [u8; 20]) -> &str {
    // Always display in sats for simplicity.
    let mut tmp = [0u8; 16];
    let s = fmt_u64(sats, &mut tmp);
    let label = b" sats";
    let slen = s.len();
    let llen = label.len();
    if slen + llen > 20 { return "? sats"; }
    buf[..slen].copy_from_slice(s.as_bytes());
    buf[slen..slen + llen].copy_from_slice(label);
    core::str::from_utf8(&buf[..slen + llen]).unwrap_or("?")
}

fn fmt_fee(sats: u64, buf: &mut [u8; 20]) -> &str {
    let mut tmp = [0u8; 16];
    let s = fmt_u64(sats, &mut tmp);
    let prefix = b"Fee: ";
    let suffix = b" sats";
    let plen = prefix.len();
    let slen = s.len();
    let sflen = suffix.len();
    if plen + slen + sflen > 20 { return "Fee: ?"; }
    buf[..plen].copy_from_slice(prefix);
    buf[plen..plen + slen].copy_from_slice(s.as_bytes());
    buf[plen + slen..plen + slen + sflen].copy_from_slice(suffix);
    core::str::from_utf8(&buf[..plen + slen + sflen]).unwrap_or("?")
}

fn fmt_to<'a>(dest: &str, buf: &'a mut [u8; 18]) -> &'a str {
    let prefix = b"To: ";
    let plen = prefix.len();
    let dlen = dest.len().min(14);
    buf[..plen].copy_from_slice(prefix);
    buf[plen..plen + dlen].copy_from_slice(&dest.as_bytes()[..dlen]);
    core::str::from_utf8(&buf[..plen + dlen]).unwrap_or("?")
}

fn fmt_u64(mut n: u64, buf: &mut [u8; 16]) -> &str {
    if n == 0 {
        buf[0] = b'0';
        return core::str::from_utf8(&buf[..1]).unwrap();
    }
    let mut pos = 16usize;
    while n > 0 {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    core::str::from_utf8(&buf[pos..]).unwrap_or("?")
}
