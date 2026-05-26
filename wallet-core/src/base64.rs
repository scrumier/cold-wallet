//! Minimal Base64 encode/decode (standard alphabet, with padding). No alloc.

const ENC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes `input` into `out` (must be at least `((input.len() + 2) / 3) * 4` bytes).
/// Returns the number of bytes written.
/// If `out` is too small the function writes nothing and returns `0`.
pub fn encode(input: &[u8], out: &mut [u8]) -> usize {
    // Pre-check: required output length = ceil(input.len() / 3) * 4.
    let required = input.len().div_ceil(3) * 4;
    if out.len() < required {
        return 0;
    }

    let mut i = 0;
    let mut o = 0;
    while i + 2 < input.len() {
        let a = input[i]     as usize;
        let b = input[i + 1] as usize;
        let c = input[i + 2] as usize;
        // Safety: pre-check guarantees o + 3 < out.len()
        out[o]     = ENC[ a >> 2];
        out[o + 1] = ENC[((a << 4) | (b >> 4)) & 0x3f];
        out[o + 2] = ENC[((b << 2) | (c >> 6)) & 0x3f];
        out[o + 3] = ENC[ c                    & 0x3f];
        i += 3;
        o += 4;
    }
    match input.len() - i {
        1 => {
            let a = input[i] as usize;
            out[o]     = ENC[ a >> 2];
            out[o + 1] = ENC[(a << 4) & 0x3f];
            out[o + 2] = b'=';
            out[o + 3] = b'=';
            o += 4;
        }
        2 => {
            let a = input[i]     as usize;
            let b = input[i + 1] as usize;
            out[o]     = ENC[ a >> 2];
            out[o + 1] = ENC[((a << 4) | (b >> 4)) & 0x3f];
            out[o + 2] = ENC[ (b << 2)             & 0x3f];
            out[o + 3] = b'=';
            o += 4;
        }
        _ => {}
    }
    o
}

/// Decodes Base64 `input` into `out`. Returns decoded byte count, or `None` on invalid input.
pub fn decode(input: &[u8], out: &mut [u8]) -> Option<usize> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' | b'-' => Some(62),   // also accept URL-safe '-'
            b'/' | b'_' => Some(63),   // also accept URL-safe '_'
            _ => None,
        }
    }

    // Strip trailing padding.
    let trimmed = input
        .iter()
        .rposition(|&b| b != b'=')
        .map(|i| &input[..i + 1])
        .unwrap_or(&[]);

    let full = trimmed.len() / 4;
    let rem  = trimmed.len() % 4;
    let mut o: usize = 0;

    for g in 0..full {
        let a = val(trimmed[g * 4]    )?;
        let b = val(trimmed[g * 4 + 1])?;
        let c = val(trimmed[g * 4 + 2])?;
        let d = val(trimmed[g * 4 + 3])?;
        // Bounds-check: each group writes 3 bytes starting at o.
        if o.checked_add(3).is_none_or(|end| end > out.len()) { return None; }
        out[o]     = (a << 2) | (b >> 4);
        out[o + 1] = (b << 4) | (c >> 2);
        out[o + 2] = (c << 6) |  d;
        o += 3;
    }

    let base = full * 4;
    match rem {
        2 => {
            let a = val(trimmed[base]    )?;
            let b = val(trimmed[base + 1])?;
            if o >= out.len() { return None; }
            out[o] = (a << 2) | (b >> 4);
            o += 1;
        }
        3 => {
            let a = val(trimmed[base]    )?;
            let b = val(trimmed[base + 1])?;
            let c = val(trimmed[base + 2])?;
            if o.checked_add(2).is_none_or(|end| end > out.len()) { return None; }
            out[o]     = (a << 2) | (b >> 4);
            out[o + 1] = (b << 4) | (c >> 2);
            o += 2;
        }
        0 => {}
        // A length of 4k+1 is impossible for valid Base64 (a single leftover
        // 6-bit group cannot encode any byte). Reject rather than silently drop.
        1 => return None,
        _ => unreachable!(),
    }

    Some(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_aligned() {
        let src = b"Hello, Bitcoin!";
        let mut enc = [0u8; 24];
        let enc_len = encode(src, &mut enc);
        let mut dec = [0u8; 24];
        let dec_len = decode(&enc[..enc_len], &mut dec).unwrap();
        assert_eq!(&dec[..dec_len], src);
    }

    #[cfg(feature = "std")]
    #[test]
    fn round_trip_unaligned() {
        for len in 0..=16usize {
            let src: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut enc = vec![0u8; (len + 2) / 3 * 4 + 4];
            let enc_len = encode(&src, &mut enc);
            let mut dec = vec![0u8; len + 4];
            let dec_len = decode(&enc[..enc_len], &mut dec).unwrap();
            assert_eq!(&dec[..dec_len], src.as_slice(), "len={len}");
        }
    }

    #[test]
    fn encode_too_small_returns_zero() {
        // "foo" encodes to 4 bytes; a 1-byte buffer is too small → return 0, no panic.
        let mut tiny = [0u8; 1];
        let n = encode(b"foo", &mut tiny);
        assert_eq!(n, 0);
        // Empty input always fits in any buffer (required = 0).
        let mut tiny2 = [0u8; 0];
        let n2 = encode(b"", &mut tiny2);
        assert_eq!(n2, 0); // 0 bytes written, no panic
    }

    #[test]
    fn decode_too_small_returns_none() {
        // "Zm9v" decodes to "foo" (3 bytes); a 1-byte buffer is too small → None, no panic.
        let mut tiny = [0u8; 1];
        let result = decode(b"Zm9v", &mut tiny);
        assert!(result.is_none(), "expected None for undersized decode buffer");
    }

    #[test]
    fn decode_rejects_lone_trailing_char() {
        // "Zm9vY" = "Zm9v" (valid) + 1 leftover char → malformed, must be None.
        let mut out = [0u8; 8];
        assert!(decode(b"Zm9vY", &mut out).is_none());
    }

    #[test]
    fn known_vectors() {
        let cases: &[(&[u8], &[u8])] = &[
            (b"",       b""),
            (b"f",      b"Zg=="),
            (b"fo",     b"Zm8="),
            (b"foo",    b"Zm9v"),
            (b"foob",   b"Zm9vYg=="),
            (b"fooba",  b"Zm9vYmE="),
            (b"foobar", b"Zm9vYmFy"),
        ];
        for (plain, encoded) in cases {
            let mut enc_buf = [0u8; 16];
            let n = encode(plain, &mut enc_buf);
            assert_eq!(&enc_buf[..n], *encoded, "encode {plain:?}");

            if encoded.is_empty() { continue; }
            let mut dec_buf = [0u8; 16];
            let m = decode(encoded, &mut dec_buf).unwrap();
            assert_eq!(&dec_buf[..m], *plain, "decode {encoded:?}");
        }
    }
}
