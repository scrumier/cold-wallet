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

/// Renders the transaction-review screen (WYSIWYS — what you see is what you sign).
///
/// ALL outputs are listed, each on its own pair of rows:
///   row 1: full `bc1p…` address (62 chars, no truncation) — or a warning for non-P2TR
///   row 2: amount in sats, tagged "(change)" if this is our own change output
///
/// Change is identified ONLY by re-deriving `our_output_key` and matching the
/// 32-byte witness program in the scriptPubKey — no host-provided metadata is
/// trusted. If `our_output_key` is `None` every output is treated as a send.
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
    let green  = MonoTextStyle::new(&FONT_6X10, Rgb565::CSS_LIME_GREEN);
    let cx     = SCREEN_W / 2;

    Text::with_alignment("Review Transaction", Point::new(cx, 18), white_text(), Center)
        .draw(display)?;

    if let Some(p) = psbt {
        // ── Classify all outputs ───────────────────────────────────────────
        let mut send_total:    u64  = 0;
        let     total_in:      u64  = p.total_in();
        let     total_out:     u64  = p.total_out();
        let     output_overflow: bool = total_out > total_in;
        let     fee:           u64  = total_in.saturating_sub(total_out);

        for i in 0..p.output_count {
            let out = &p.outputs[i];
            if !is_change(out, our_output_key.as_ref()) {
                send_total = send_total.saturating_add(out.amount_sats);
            }
        }

        // ── Summary header: send total + fee ──────────────────────────────
        {
            let mut sbuf = [0u8; 28];
            let send_str = fmt_with_prefix_suffix(b"Send: ", send_total, b" sats", &mut sbuf);
            Text::with_alignment(send_str, Point::new(cx / 2, 35), small, Center)
                .draw(display)?;
        }
        {
            let mut fbuf = [0u8; 28];
            let fee_str = fmt_with_prefix_suffix(b"Fee: ", fee, b" sats", &mut fbuf);
            let fee_style = if fee_is_abnormal(fee, send_total, total_in) { yellow } else { small };
            Text::with_alignment(fee_str, Point::new(cx + cx / 2, 35), fee_style, Center)
                .draw(display)?;
        }

        // Fee abnormality warning (shown below the header row)
        if output_overflow {
            Text::with_alignment(
                "! OUTPUTS EXCEED INPUTS — invalid tx !",
                Point::new(cx, 50),
                yellow,
                Center,
            ).draw(display)?;
        } else if fee_is_abnormal(fee, send_total, total_in) {
            Text::with_alignment(
                "! HIGH FEE — verify before signing !",
                Point::new(cx, 50),
                yellow,
                Center,
            ).draw(display)?;
        }

        // ── Per-output rows ────────────────────────────────────────────────
        // Each output occupies OUTPUT_SLOT px: address row at offset 0,
        // amount/label row at offset ADDR_H.
        // With MAX_OUTPUTS=8 and OUTPUT_SLOT=24: 8×24 = 192px → rows y=65..257
        const OUTPUT_START_Y: i32 =  65;
        const ADDR_H:         i32 =  12; // baseline of address text within slot
        const OUTPUT_SLOT:    i32 =  24; // total height per output

        // Column separator between outputs list and the right edge — thin
        // horizontal rule below the header.
        // (no line primitives needed — just the text rows suffice)

        for i in 0..p.output_count {
            let out    = &p.outputs[i];
            let slot_y = OUTPUT_START_Y + (i as i32) * OUTPUT_SLOT;
            let addr_y = slot_y + ADDR_H;
            let meta_y = slot_y + OUTPUT_SLOT - 2; // 2px from bottom of slot

            let change = is_change(out, our_output_key.as_ref());

            // Row 1: full address or non-P2TR warning
            let mut addr_buf = [0u8; 62];
            if let Some(addr_str) = output_address(out, &mut addr_buf) {
                let addr_style = if change { green } else { mono };
                Text::with_alignment(addr_str, Point::new(cx, addr_y), addr_style, Center)
                    .draw(display)?;
            } else {
                Text::with_alignment(
                    "(non-P2TR output — address not shown)",
                    Point::new(cx, addr_y),
                    yellow,
                    Center,
                ).draw(display)?;
            }

            // Row 2: amount + optional "(change)" tag
            if change {
                let mut meta_buf = [0u8; 40];
                let meta_str = fmt_with_suffix_change(out.amount_sats, &mut meta_buf);
                Text::with_alignment(meta_str, Point::new(cx, meta_y), green, Center)
                    .draw(display)?;
            } else {
                let mut amt_buf = [0u8; 28];
                let amt_str = fmt_with_suffix(out.amount_sats, b" sats", &mut amt_buf);
                Text::with_alignment(amt_str, Point::new(cx, meta_y), mono, Center)
                    .draw(display)?;
            }
        }

        // ── Self-send notice (no non-change outputs) ───────────────────────
        if send_total == 0 && p.output_count > 0 {
            let notice_y = OUTPUT_START_Y + (p.output_count as i32) * OUTPUT_SLOT + 10;
            Text::with_alignment(
                "All outputs return to this wallet",
                Point::new(cx, notice_y),
                yellow,
                Center,
            ).draw(display)?;
        }

    } else {
        Text::with_alignment("Loading…", Point::new(cx, 200), small, Center).draw(display)?;
    }

    draw_button(display, NAV_PREV_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, "Cancel", white_stroke(2), white_text())?;
    draw_button(display, NAV_NEXT_X, NAV_BTN_Y, NAV_BTN_W, NAV_BTN_H, "Sign >", white_stroke(2), white_text())?;

    Ok(())
}

// ── Classification ────────────────────────────────────────────────────────────

/// Returns `true` only if `out` is our own change, verified by re-deriving the
/// wallet's output key and comparing to the 32-byte witness program in the
/// scriptPubKey (P2TR, `OP_1 OP_PUSHBYTES_32 <key>`).
///
/// If `our_output_key` is `None` (seed temporarily unloaded / not available)
/// this function returns `false` — treating every output as a send is the safe
/// default, because accepting host-provided metadata (PSBT_OUT_TAP_INTERNAL_KEY)
/// would allow a malicious coordinator to disguise its own output as change.
fn is_change(out: &TxOutput, our_output_key: Option<&[u8; 32]>) -> bool {
    let Some(ok) = our_output_key else { return false };
    let Some(wp) = output_witness_program(out) else { return false };
    wp == ok
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

// ── Fee sanity check ──────────────────────────────────────────────────────────

/// Returns `true` when the fee looks abnormally high.
///
/// Rules (no float, no alloc):
///   - Fee exceeds 25% of total inputs (`fee > total_in / 4`), OR
///   - For an actual spend (`send_total > 0`): fee exceeds the amount being
///     sent (`fee > send_total`).
///
/// The `send_total > 0` guard avoids a false positive on consolidations /
/// self-sends, where every output is our own change so `send_total == 0`: there
/// any non-zero fee would otherwise always exceed `send_total` and warn. Such
/// transactions are still covered by the 25%-of-inputs rule.
pub(crate) fn fee_is_abnormal(fee: u64, send_total: u64, total_in: u64) -> bool {
    fee > total_in / 4 || (send_total > 0 && fee > send_total)
}

// ── Formatting helpers (no_std, no alloc) ─────────────────────────────────────

fn fmt_with_suffix<'a>(n: u64, suffix: &[u8], buf: &'a mut [u8; 28]) -> &'a str {
    let mut tmp = [0u8; 20];
    let s = fmt_u64(n, &mut tmp);
    if s.len() + suffix.len() > buf.len() { return "?"; }
    buf[..s.len()].copy_from_slice(s.as_bytes());
    buf[s.len()..s.len() + suffix.len()].copy_from_slice(suffix);
    core::str::from_utf8(&buf[..s.len() + suffix.len()]).unwrap_or("?")
}

fn fmt_with_prefix_suffix<'a>(prefix: &[u8], n: u64, suffix: &[u8], buf: &'a mut [u8; 28]) -> &'a str {
    let mut tmp = [0u8; 20];
    let s = fmt_u64(n, &mut tmp);
    let total = prefix.len() + s.len() + suffix.len();
    if total > buf.len() { return "?"; }
    buf[..prefix.len()].copy_from_slice(prefix);
    buf[prefix.len()..prefix.len() + s.len()].copy_from_slice(s.as_bytes());
    buf[prefix.len() + s.len()..total].copy_from_slice(suffix);
    core::str::from_utf8(&buf[..total]).unwrap_or("?")
}

/// Formats `"N sats (change)"` into a 40-byte buffer.
fn fmt_with_suffix_change(n: u64, buf: &mut [u8; 40]) -> &str {
    let suffix = b" sats (change)";
    let mut tmp = [0u8; 20];
    let s = fmt_u64(n, &mut tmp);
    let total = s.len() + suffix.len();
    if total > buf.len() { return "?"; }
    buf[..s.len()].copy_from_slice(s.as_bytes());
    buf[s.len()..total].copy_from_slice(suffix);
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

    fn non_p2tr_output(amount: u64) -> TxOutput {
        // OP_0 OP_PUSHBYTES_20 <20 bytes> — P2WPKH, not P2TR
        let mut spk = [0u8; MAX_SPK_LEN];
        spk[0] = 0x00; spk[1] = 0x14;
        TxOutput { amount_sats: amount, script_pubkey: spk, script_len: 22, tap_internal_key: None }
    }

    // ── is_change tests ───────────────────────────────────────────────────

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

    /// L4: when our_output_key is None, host-flagged outputs must NOT be
    /// treated as change, even if tap_internal_key is set by the host.
    #[test]
    fn is_change_false_when_no_output_key_even_with_host_metadata() {
        let mut out = p2tr_output(50_000, [0xcc; 32]);
        out.tap_internal_key = Some([0xcc; 32]); // host sets the flag
        // No our_output_key → safe default: not change.
        assert!(!is_change(&out, None));
    }

    #[test]
    fn is_change_false_for_non_p2tr_even_with_matching_key() {
        // Non-P2TR outputs can never be our change.
        let out = non_p2tr_output(10_000);
        assert!(!is_change(&out, Some(&[0xaa; 32])));
    }

    // ── output_address tests ──────────────────────────────────────────────

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
    fn output_address_none_for_non_p2tr() {
        let out = non_p2tr_output(1000);
        let mut buf = [0u8; 62];
        assert!(output_address(&out, &mut buf).is_none());
    }

    // ── fee_is_abnormal tests ─────────────────────────────────────────────

    /// Fee == 0: never abnormal.
    #[test]
    fn fee_abnormal_zero_fee_is_fine() {
        assert!(!fee_is_abnormal(0, 100_000, 200_000));
    }

    /// Fee < send_total AND fee <= total_in/4: normal.
    #[test]
    fn fee_abnormal_small_fee_is_fine() {
        // send=80_000, fee=5_000, total_in=100_000 → 5000 <= 80000 AND 5000 <= 25000 → normal
        assert!(!fee_is_abnormal(5_000, 80_000, 100_000));
    }

    /// Fee > send_total triggers warning (even if fee <= 25% of total_in).
    #[test]
    fn fee_abnormal_fee_exceeds_send_total() {
        // send=1_000, fee=2_000, total_in=100_000 → fee > send_total → abnormal
        assert!(fee_is_abnormal(2_000, 1_000, 100_000));
    }

    /// Fee > total_in/4 triggers warning (even if fee < send_total).
    #[test]
    fn fee_abnormal_fee_exceeds_25_percent() {
        // send=80_000, fee=30_000, total_in=100_000 → 30000 > 25000 → abnormal
        assert!(fee_is_abnormal(30_000, 80_000, 100_000));
    }

    /// Self-send / consolidation (send_total == 0): a reasonable fee must NOT
    /// warn (no false positive), but the 25%-of-inputs rule still applies.
    #[test]
    fn fee_abnormal_self_send_reasonable_fee_is_fine() {
        // fee=1_000, total_in=100_000 → 1000 <= 25000, send_total==0 → not abnormal
        assert!(!fee_is_abnormal(1_000, 0, 100_000));
    }

    #[test]
    fn fee_abnormal_self_send_huge_fee_warns() {
        // fee=30_000 > total_in/4 (25_000) → abnormal even on a self-send
        assert!(fee_is_abnormal(30_000, 0, 100_000));
    }

    /// Exactly at the 25% boundary (fee == total_in/4): NOT abnormal (strict >).
    #[test]
    fn fee_abnormal_exactly_25_percent_is_fine() {
        // fee = total_in / 4, send_total large → neither rule fires
        assert!(!fee_is_abnormal(25_000, 70_000, 100_000));
    }

    /// One tick above 25%: abnormal.
    #[test]
    fn fee_abnormal_one_over_25_percent() {
        assert!(fee_is_abnormal(25_001, 70_000, 100_000));
    }

    // ── fmt helpers ───────────────────────────────────────────────────────

    #[test]
    fn fmt_helpers_no_panic_on_overflow_with_suffix() {
        let mut buf = [0u8; 28];
        // u64::MAX = 20 digits; "? sats" needs 5 → 25 > 28? No, 25 < 28.
        // Actually 20 + 5 = 25 <= 28: should NOT return "?".
        let s = fmt_with_suffix(u64::MAX, b" sats", &mut buf);
        assert!(s.ends_with(" sats"), "got: {s}");
    }

    #[test]
    fn fmt_with_suffix_change_basic() {
        let mut buf = [0u8; 40];
        let s = fmt_with_suffix_change(50_000, &mut buf);
        assert_eq!(s, "50000 sats (change)");
    }

    #[test]
    fn fmt_with_prefix_suffix_basic() {
        let mut buf = [0u8; 28];
        let s = fmt_with_prefix_suffix(b"Fee: ", 1_234, b" sats", &mut buf);
        assert_eq!(s, "Fee: 1234 sats");
    }

    // ── multi-output classification ───────────────────────────────────────

    /// Verify that with two outputs (one ours, one theirs), is_change correctly
    /// classifies each, and send_total excludes change.
    #[test]
    fn multi_output_classification() {
        let our_key = [0xaa; 32];
        let their_key = [0xbb; 32];

        let change_out = p2tr_output(20_000, our_key);
        let send_out   = p2tr_output(80_000, their_key);

        assert!( is_change(&change_out, Some(&our_key)));
        assert!(!is_change(&send_out,   Some(&our_key)));

        // send_total computation mirrors draw()
        let outputs = [&send_out, &change_out];
        let send_total: u64 = outputs.iter()
            .filter(|o| !is_change(o, Some(&our_key)))
            .map(|o| o.amount_sats)
            .sum();
        assert_eq!(send_total, 80_000);
    }

    /// Without our_output_key, all outputs — including those with host metadata —
    /// are classified as sends.
    #[test]
    fn multi_output_all_send_when_no_key() {
        let our_key = [0xaa; 32];

        let mut flagged = p2tr_output(20_000, our_key);
        flagged.tap_internal_key = Some(our_key); // host flags it as change

        let send_out = p2tr_output(80_000, [0xbb; 32]);

        // Without our_output_key both are sends.
        assert!(!is_change(&flagged,  None));
        assert!(!is_change(&send_out, None));

        let outputs = [&flagged, &send_out];
        let send_total: u64 = outputs.iter()
            .filter(|o| !is_change(o, None))
            .map(|o| o.amount_sats)
            .sum();
        assert_eq!(send_total, 100_000); // both counted as sends
    }
}
