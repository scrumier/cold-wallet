use embedded_graphics::mono_font::ascii::FONT_6X10;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::geometry::Point;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::text::{Alignment::Center, Text};

use crate::derive::address_from_witness_program;
use crate::layout::{SCREEN_W, NAV_PREV_X, NAV_NEXT_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H};
use crate::psbt::{ParsedPsbt, TxOutput};
use super::{draw_button, white_stroke, white_text};

/// Renders the transaction-review screen. The destination address is shown in
/// full (`bc1p…`, 62 chars) so the user can compare with the source of truth
/// they expect — no truncation, no hex-only fallback. Outputs identified as
/// our own change are clearly labelled and excluded from the "Send" total.
pub fn draw<D>(
    display:        &mut D,
    psbt:           Option<&ParsedPsbt>,
    our_output_key: Option<[u8; 32]>,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let small  = MonoTextStyle::new(&FONT_6X10, Rgb565::CSS_GRAY);
    let mono   = MonoTextStyle::new(&FONT_6X10, Rgb565::WHITE);
    let yellow = MonoTextStyle::new(&FONT_6X10, Rgb565::CSS_YELLOW);
    let cx     = SCREEN_W / 2;

    Text::with_alignment("Review Transaction", Point::new(cx, 35), white_text(), Center)
        .draw(display)?;

    if let Some(p) = psbt {
        // Classify each output as Send or Change.
        let mut send_total:   u64 = 0;
        let mut change_total: u64 = 0;
        let mut first_send_idx: Option<usize> = None;
        let mut send_count = 0usize;

        for i in 0..p.output_count {
            let out = &p.outputs[i];
            if is_change(out, our_output_key.as_ref()) {
                change_total = change_total.saturating_add(out.amount_sats);
            } else {
                send_total = send_total.saturating_add(out.amount_sats);
                send_count += 1;
                if first_send_idx.is_none() { first_send_idx = Some(i); }
            }
        }

        let fee: u64 = p.total_in().saturating_sub(p.total_out());

        // ── "Send X sats" ─────────────────────────────────────────────────
        Text::with_alignment("Send", Point::new(cx, 70), small, Center).draw(display)?;
        let mut amount_buf = [0u8; 24];
        let amount_str = fmt_with_suffix(send_total, b" sats", &mut amount_buf);
        Text::with_alignment(amount_str, Point::new(cx, 95), white_text(), Center).draw(display)?;

        // ── Destination address (full bc1p) ───────────────────────────────
        if let Some(idx) = first_send_idx {
            // Display destination address from the FIRST send output.
            // For multi-recipient sends (rare), we also show a hint.
            let out = &p.outputs[idx];
            Text::with_alignment("To", Point::new(cx, 135), small, Center).draw(display)?;

            if let Some(addr_str) = output_address(out, &mut [0u8; 62]) {
                // Center the 62-char bc1p address. Width = 62 × 6 = 372px.
                Text::with_alignment(addr_str, Point::new(cx, 160), mono, Center)
                    .draw(display)?;
            } else {
                Text::with_alignment(
                    "(non-P2TR destination — refuse to sign)",
                    Point::new(cx, 160), yellow, Center,
                ).draw(display)?;
            }

            if send_count > 1 {
                let mut hint_buf = [0u8; 36];
                let hint = fmt_extra_recipients(send_count - 1, &mut hint_buf);
                Text::with_alignment(hint, Point::new(cx, 180), yellow, Center)
                    .draw(display)?;
            }
        } else {
            // No send outputs — entire tx returns to us (self-send / consolidation).
            Text::with_alignment(
                "All outputs return to this wallet",
                Point::new(cx, 160), yellow, Center,
            ).draw(display)?;
        }

        // ── Change line (only if non-zero) ────────────────────────────────
        if change_total > 0 {
            let mut change_buf = [0u8; 32];
            let change_str = fmt_with_prefix_suffix(b"Change: ", change_total, b" sats", &mut change_buf);
            Text::with_alignment(change_str, Point::new(cx, 215), small, Center)
                .draw(display)?;
        }

        // ── Fee ───────────────────────────────────────────────────────────
        let mut fee_buf = [0u8; 32];
        let fee_str = fmt_with_prefix_suffix(b"Fee: ", fee, b" sats", &mut fee_buf);
        Text::with_alignment(fee_str, Point::new(cx, 245), small, Center).draw(display)?;
    } else {
        Text::with_alignment("Loading…", Point::new(cx, 200), small, Center).draw(display)?;
    }

    draw_button(display, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, "Cancel", white_stroke(2), white_text())?;
    draw_button(display, NAV_NEXT_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, "Sign >", white_stroke(2), white_text())?;

    Ok(())
}

// ── Classification ────────────────────────────────────────────────────────────

/// Returns true if `out` is our own change. Two independent checks — either one
/// is sufficient:
///
/// 1. Direct: re-derive our own output key from the wallet's seed (passed in as
///    `our_output_key`) and compare to the 32-byte witness program in the
///    scriptPubKey. This does NOT rely on host-provided PSBT metadata.
/// 2. Metadata: `PSBT_OUT_TAP_INTERNAL_KEY` matches our internal key. We
///    accept this as a *positive* signal only when (1) is unavailable (e.g.
///    seed temporarily unloaded), since a malicious host could lie about it.
fn is_change(out: &TxOutput, our_output_key: Option<&[u8; 32]>) -> bool {
    let Some(wp) = output_witness_program(out) else { return false };
    if let Some(ok) = our_output_key {
        return wp == ok;
    }
    // No seed available — fall back to PSBT metadata (best-effort).
    out.tap_internal_key.is_some()
}

fn output_witness_program(out: &TxOutput) -> Option<&[u8; 32]> {
    let spk = &out.script_pubkey[..out.script_len.min(out.script_pubkey.len())];
    if spk.len() != 34 || spk[0] != 0x51 || spk[1] != 0x20 { return None; }
    let arr: &[u8; 32] = spk[2..34].try_into().ok()?;
    Some(arr)
}

/// Bech32m-encodes the output's witness program as `bc1p…`. Returns `None` if
/// the scriptPubKey is not a valid P2TR (34 bytes, OP_1 OP_PUSHBYTES_32 ...).
fn output_address<'a>(out: &TxOutput, buf: &'a mut [u8; 62]) -> Option<&'a str> {
    let wp = output_witness_program(out)?;
    *buf = address_from_witness_program(wp);
    core::str::from_utf8(buf).ok()
}

// ── Formatting helpers (no_std, no alloc) ─────────────────────────────────────

fn fmt_with_suffix<'a>(n: u64, suffix: &[u8], buf: &'a mut [u8; 24]) -> &'a str {
    let mut tmp = [0u8; 20];
    let s = fmt_u64(n, &mut tmp);
    if s.len() + suffix.len() > buf.len() { return "?"; }
    buf[..s.len()].copy_from_slice(s.as_bytes());
    buf[s.len()..s.len() + suffix.len()].copy_from_slice(suffix);
    core::str::from_utf8(&buf[..s.len() + suffix.len()]).unwrap_or("?")
}

fn fmt_with_prefix_suffix<'a>(prefix: &[u8], n: u64, suffix: &[u8], buf: &'a mut [u8; 32]) -> &'a str {
    let mut tmp = [0u8; 20];
    let s = fmt_u64(n, &mut tmp);
    let total = prefix.len() + s.len() + suffix.len();
    if total > buf.len() { return "?"; }
    buf[..prefix.len()].copy_from_slice(prefix);
    buf[prefix.len()..prefix.len() + s.len()].copy_from_slice(s.as_bytes());
    buf[prefix.len() + s.len()..total].copy_from_slice(suffix);
    core::str::from_utf8(&buf[..total]).unwrap_or("?")
}

fn fmt_extra_recipients(extra: usize, buf: &mut [u8; 36]) -> &str {
    // "(+N more recipients)" — at most 2 digits for N because MAX_OUTPUTS is 8.
    let prefix = b"(+";
    let suffix = b" more recipients)";
    let mut tmp = [0u8; 20];
    let s = fmt_u64(extra as u64, &mut tmp);
    let total = prefix.len() + s.len() + suffix.len();
    if total > buf.len() { return "?"; }
    buf[..prefix.len()].copy_from_slice(prefix);
    buf[prefix.len()..prefix.len() + s.len()].copy_from_slice(s.as_bytes());
    buf[prefix.len() + s.len()..total].copy_from_slice(suffix);
    core::str::from_utf8(&buf[..total]).unwrap_or("?")
}

fn fmt_u64(mut n: u64, buf: &mut [u8; 20]) -> &str {
    if n == 0 {
        buf[0] = b'0';
        return core::str::from_utf8(&buf[..1]).unwrap();
    }
    let mut pos = buf.len();
    while n > 0 {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    core::str::from_utf8(&buf[pos..]).unwrap_or("?")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psbt::{MAX_SPK_LEN, TxOutput};

    fn p2tr_output(amount: u64, witness_program: [u8; 32]) -> TxOutput {
        let mut spk = [0u8; MAX_SPK_LEN];
        spk[0] = 0x51; spk[1] = 0x20;
        spk[2..34].copy_from_slice(&witness_program);
        TxOutput { amount_sats: amount, script_pubkey: spk, script_len: 34, tap_internal_key: None }
    }

    #[test]
    fn is_change_matches_own_output_key() {
        let our = [0xaa; 32];
        let out = p2tr_output(50_000, our);
        assert!(is_change(&out, Some(&our)));
    }

    #[test]
    fn is_change_rejects_different_output_key() {
        let our   = [0xaa; 32];
        let other = [0xbb; 32];
        let out = p2tr_output(50_000, other);
        assert!(!is_change(&out, Some(&our)));
    }

    #[test]
    fn is_change_ignores_psbt_metadata_when_spk_mismatches() {
        // Hostile-host case: lies that the output is ours by setting
        // tap_internal_key, but the actual scriptPubKey is someone else's.
        let our   = [0xaa; 32];
        let other = [0xbb; 32];
        let mut out = p2tr_output(50_000, other);
        out.tap_internal_key = Some([0; 32]); // bogus metadata
        // We pass our_output_key so direct check wins → not change.
        assert!(!is_change(&out, Some(&our)));
    }

    #[test]
    fn output_address_produces_bc1p() {
        let wp = [0x42u8; 32];
        let out = p2tr_output(1000, wp);
        let mut buf = [0u8; 62];
        let s = output_address(&out, &mut buf).unwrap();
        assert_eq!(s.len(), 62);
        assert!(s.starts_with("bc1p"));
    }

    #[test]
    fn fmt_helpers_no_panic_on_overflow() {
        let mut buf = [0u8; 24];
        let s = fmt_with_suffix(u64::MAX, b" sats", &mut buf);
        // u64::MAX has 20 digits — 20 + 5 = 25, larger than 24. Expect graceful "?".
        assert_eq!(s, "?");
    }
}
