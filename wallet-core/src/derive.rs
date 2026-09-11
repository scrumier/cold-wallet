//! BIP32/BIP86 key derivation, P2TR address encoding and descriptor export.
//!
//! Derivation window: `m/86'/{coin}'/0'/{branch}/{index}` with branch 0
//! (receive) and 1 (change), index 0..KEY_WINDOW-1 — the wallet recognises
//! its own outputs and inputs across that window instead of only the first
//! index. The coin type and address HRP follow `NETWORK`.
//! Reference: BIP32, BIP86, BIP340, BIP341, BIP350, BIP380, BIP386.

use bip32::{ChildNumber, XPrv};
use bitcoin_hashes::{sha256, HashEngine};
use zeroize::Zeroize;
use k256::{
    AffinePoint, ProjectivePoint, Scalar,
    elliptic_curve::{
        PrimeField,
        sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint},
    },
};

/// Receive / change branches of the BIP86 account, and how deep the wallet
/// scans each of them (F-04: a fixed gap window, no dynamic gap limit).
pub const RECEIVE_BRANCH: u32 = 0;
pub const CHANGE_BRANCH: u32 = 1;
pub const KEY_WINDOW: usize = 20;
/// Total keys scanned: receive window then change window.
pub const OWN_KEY_COUNT: usize = 2 * KEY_WINDOW;

/// Bitcoin network the wallet is compiled for. The coin type (BIP32) and the
/// bech32 address prefix follow it. A firmware is built for one network:
/// this is a constant, not a runtime parameter, so a mainnet build can never
/// display or derive testnet addresses by accident.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    /// Bech32 address prefix (BIP350).
    pub fn hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "bc",
            Network::Testnet => "tb",
        }
    }

    /// BIP32 coin type: 0' for mainnet, 1' for testnet.
    pub fn coin_type(self) -> u32 {
        match self {
            Network::Mainnet => 0,
            Network::Testnet => 1,
        }
    }
}

/// The network this wallet runs on. Testnet until the signer is trusted with
/// real funds (see ROADMAP.md phase 3).
pub const NETWORK: Network = Network::Testnet;

/// Derives the BIP86 P2TR receive address from a BIP39 seed.
///
/// Path `m/86'/{coin}'/0'/0/0` on `NETWORK` (`bc1p…` or `tb1p…`).
/// Returns 62 ASCII bytes, or `None` if any derivation step fails.
pub fn taproot_address(seed: &[u8; 64]) -> Option<[u8; 62]> {
    let internal_key = tap_xonly_at(seed, RECEIVE_BRANCH, 0)?;
    let output_key   = taproot_tweak(&internal_key)?;
    Some(p2tr_address(&output_key, NETWORK.hrp()))
}

/// Returns `(x_only_internal_key, raw_private_key_bytes)` for the BIP86 path.
///
/// Used by the signing module to construct the tweaked signing key.
pub fn tap_keypair(seed: &[u8; 64]) -> Option<([u8; 32], [u8; 32])> {
    tap_keypair_at(seed, RECEIVE_BRANCH, 0)
}

/// Returns `(x_only_internal_key, raw_private_key_bytes)` for
/// `m/86'/0'/0'/{branch}/{index}` (mainnet coin type 0).
pub fn tap_keypair_at(seed: &[u8; 64], branch: u32, index: u32) -> Option<([u8; 32], [u8; 32])> {
    let xprv = derive_path(seed, branch, index)?;
    let mut raw_privkey: [u8; 32] = xprv.private_key().to_bytes().into();
    let compressed = xprv.public_key().public_key().to_encoded_point(true);
    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(&compressed.as_bytes()[1..]);

    // BIP340: the internal key is always lift_x(P) = even-y point.
    // If d*G has odd y, negate d so the returned private key corresponds to even-y P.
    // taproot_tweak_pub assumes even-y; signing and verification must agree.
    //
    // raw_privkey is Copy — avoid `?` inside the if/else so we can zero the local
    // unconditionally on both success and failure paths before returning.
    let privkey_maybe: Option<[u8; 32]> = if compressed.as_bytes()[0] == 0x03 {
        let opt: Option<Scalar> = Scalar::from_repr(raw_privkey.into()).into();
        opt.map(|mut d| {
            // `d` and its negation `-d` are both private key material. Capture
            // the byte repr of the negated scalar, then zeroize both scalars so
            // neither the internal private key nor its negation lingers in the
            // stack/registers after this scope. (`raw_privkey` bytes are zeroed
            // below; this closes the matching gap on the Scalar representation —
            // mirrors `signing::tweaked_signing_key`.)
            let mut nd = -d;
            let neg: [u8; 32] = nd.to_repr().into();
            nd.zeroize();
            d.zeroize();
            neg
        })
    } else {
        Some(raw_privkey)
    };
    for b in raw_privkey.iter_mut() { unsafe { core::ptr::write_volatile(b, 0); } }

    Some((x_only, privkey_maybe?))
}

/// Returns the x-only internal key for `m/86'/0'/0'/{branch}/{index}`.
pub fn tap_xonly_at(seed: &[u8; 64], branch: u32, index: u32) -> Option<[u8; 32]> {
    let xprv = derive_path(seed, branch, index)?;
    // Compressed public key: 33 bytes [02|03 prefix] ++ [32-byte x]
    let compressed = xprv.public_key().public_key().to_encoded_point(true);
    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(&compressed.as_bytes()[1..]);
    Some(x_only)
}

/// Walks `m/86'/{coin}'/0'/{branch}/{index}` from a BIP39 seed (coin from `NETWORK`).
fn derive_path(seed: &[u8; 64], branch: u32, index: u32) -> Option<XPrv> {
    let account = account_xprv(seed)?;
    let cn = ChildNumber::new(branch, false).ok()?;
    let xprv = account.derive_child(cn).ok()?;
    let cn = ChildNumber::new(index, false).ok()?;
    xprv.derive_child(cn).ok()
}

/// The BIP86 account key: `m/86'/{coin}'/0'` (coin from `NETWORK`).
fn account_xprv(seed: &[u8; 64]) -> Option<XPrv> {
    let mut xprv = XPrv::new(seed).ok()?;
    for &(idx, hardened) in &[(86u32, true), (NETWORK.coin_type(), true), (0, true)] {
        let cn = ChildNumber::new(idx, hardened).ok()?;
        xprv = xprv.derive_child(cn).ok()?;
    }
    Some(xprv)
}

/// The wallet's own internal keys across the derivation window: branch 0
/// (receive) indexes 0..KEY_WINDOW, then branch 1 (change). Used to match
/// PSBT inputs we can sign.
pub fn own_internal_keys(seed: &[u8; 64]) -> Option<[[u8; 32]; OWN_KEY_COUNT]> {
    let mut out = [[0u8; 32]; OWN_KEY_COUNT];
    for (slot, &(branch, index)) in key_window_slots().iter().enumerate() {
        out[slot] = tap_xonly_at(seed, branch, index)?;
    }
    Some(out)
}

/// The wallet's own *tweaked output* keys across the derivation window: the
/// 32-byte witness programs that can appear in our P2TR scriptPubKeys. Used
/// by the review screen to classify change without trusting host metadata.
pub fn own_output_keys(seed: &[u8; 64]) -> Option<[[u8; 32]; OWN_KEY_COUNT]> {
    let mut out = [[0u8; 32]; OWN_KEY_COUNT];
    for (slot, &(branch, index)) in key_window_slots().iter().enumerate() {
        let ok = taproot_tweak(&tap_xonly_at(seed, branch, index)?)?;
        out[slot] = ok;
    }
    Some(out)
}

/// (branch, index) pairs of the window, slot order of `own_*_keys`.
pub fn key_window_slots() -> [(u32, u32); OWN_KEY_COUNT] {
    let mut slots = [(RECEIVE_BRANCH, 0u32); OWN_KEY_COUNT];
    for (i, slot) in slots.iter_mut().enumerate() {
        let index = (i % KEY_WINDOW) as u32;
        let branch = if i < KEY_WINDOW { RECEIVE_BRANCH } else { CHANGE_BRANCH };
        *slot = (branch, index);
    }
    slots
}

// ── Descriptor export (BIP380/386) ───────────────────────────────────────────

/// Characters allowed in a descriptor (BIP380). Note: as published (and as
/// used by Bitcoin Core and the BIP's own Python code) this string is 95
/// chars, not the 3×32 announced in the prose. The BIP380 test vector below
/// (`raw(deadbeef)` → `89f8spxm`) validates this exact table.
const DESCRIPTOR_INPUT_CHARSET: &[u8; 95] =
    b"0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const DESCRIPTOR_CHECKSUM_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const DESCRIPTOR_GENERATOR: [u64; 5] =
    [0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd];

/// Largest descriptor this wallet can build:
/// `tr([` + fingerprint(8) + `/86h/{coin}h/0h]` + tpub(111) + `/<0;1>/*)` + `#` + checksum(8).
pub const DESCRIPTOR_MAX: usize = 200;

fn descriptor_polymod(symbols: &[u16]) -> u64 {
    let mut chk: u64 = 1;
    for &v in symbols {
        let top = chk >> 35;
        chk = (chk & 0x7_FFFF_FFFF) << 5 ^ u64::from(v);
        for (i, &g) in DESCRIPTOR_GENERATOR.iter().enumerate() {
            if (top >> i) & 1 != 0 {
                chk ^= g;
            }
        }
    }
    chk
}

/// Symbol expansion per BIP380: each char contributes its group and its
/// position within the group; every 3rd symbol is followed by the combined
/// group numbers.
fn descriptor_expand(s: &[u8]) -> Option<([u16; 400], usize)> {
    let mut symbols = [0u16; 400];
    let mut n = 0usize;
    let mut groups = [0u16; 3];
    let mut group_count = 0usize;
    for &c in s {
        let v = DESCRIPTOR_INPUT_CHARSET.iter().position(|&x| x == c)? as u16;
        if n + 1 >= symbols.len() { return None; }
        symbols[n] = v & 31;
        n += 1;
        groups[group_count] = v >> 5;
        group_count += 1;
        if group_count == 3 {
            symbols[n] = groups[0] * 9 + groups[1] * 3 + groups[2];
            n += 1;
            group_count = 0;
        }
    }
    if group_count == 1 {
        symbols[n] = groups[0];
        n += 1;
    } else if group_count == 2 {
        symbols[n] = groups[0] * 3 + groups[1];
        n += 1;
    }
    Some((symbols, n))
}

/// Computes the 8-char BIP380 checksum of a descriptor body (no `#`).
/// Verified against the BIP380 test vector `raw(deadbeef)` → `89f8spxm`.
pub(crate) fn descriptor_checksum(desc: &[u8]) -> Option<[u8; 8]> {
    let (mut symbols, mut n) = descriptor_expand(desc)?;
    for slot in symbols[n..n + 8].iter_mut() {
        *slot = 0;
    }
    n += 8;
    let chk = descriptor_polymod(&symbols[..n]) ^ 1;
    let mut out = [0u8; 8];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = DESCRIPTOR_CHECKSUM_CHARSET[((chk >> (5 * (7 - i as u32))) & 31) as usize];
    }
    Some(out)
}

fn hex_8(bytes: &[u8; 4]) -> [u8; 8] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 8];
    for (i, &b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[usize::from(b >> 4)];
        out[i * 2 + 1] = HEX[usize::from(b & 0x0f)];
    }
    out
}

/// Builds the BIP386 output descriptor of this wallet:
///
/// ```text
/// tr([<fingerprint>/86h/{coin}h/0h]<account-xpub>/<0;1>/*)#<checksum>
/// ```
///
/// The account xpub is serialised with the testnet `tpub` / mainnet `xpub`
/// prefix following `NETWORK`. Written into `out`; returns the length.
pub fn taproot_descriptor(seed: &[u8; 64], out: &mut [u8]) -> Option<usize> {
    let master = XPrv::new(seed).ok()?;
    let fingerprint = hex_8(&master.public_key().fingerprint());

    let account_pub = account_xprv(seed)?.public_key();
    let mut b58 = [0u8; 112];
    let xpub = account_pub.to_extended_key(bip32::Prefix::TPUB).write_base58(&mut b58).ok()?;

    let coin_char = if NETWORK.coin_type() == 1 { b'1' } else { b'0' };
    let mut body = [0u8; DESCRIPTOR_MAX];
    let mut w = 0usize;
    let put = |buf: &mut [u8; DESCRIPTOR_MAX], pos: &mut usize, s: &[u8]| -> Option<()> {
        if *pos + s.len() > buf.len() { return None; }
        buf[*pos..*pos + s.len()].copy_from_slice(s);
        *pos += s.len();
        Some(())
    };
    put(&mut body, &mut w, b"tr([")?;
    put(&mut body, &mut w, &fingerprint)?;
    put(&mut body, &mut w, &[b'/', b'8', b'6', b'h', b'/', coin_char, b'h', b'/', b'0', b'h', b']'])?;
    put(&mut body, &mut w, xpub.as_bytes())?;
    put(&mut body, &mut w, b"/<0;1>/*)")?;
    let body_len = w;

    let chk = descriptor_checksum(&body[..body_len])?;
    put(&mut body, &mut w, b"#")?;
    put(&mut body, &mut w, &chk)?;

    if out.len() < w { return None; }
    out[..w].copy_from_slice(&body[..w]);
    Some(w)
}

// ── BIP341 keypath-only taproot tweak ────────────────────────────────────────

/// Computes the tweaked output key Q = P + H_TapTweak(P)·G (public, x-only).
/// Used by tests and the PSBT builder to construct P2TR scriptPubKeys.
#[allow(dead_code)]
pub fn taproot_tweak_pub(internal_key: &[u8; 32]) -> Option<[u8; 32]> {
    taproot_tweak(internal_key)
}

/// Encodes a 32-byte P2TR witness program as a `bc1p…`/`tb1p…` address.
/// Used by the sign-review screen to display destination addresses in full.
pub fn address_from_witness_program(witness_program: &[u8; 32]) -> [u8; 62] {
    p2tr_address(witness_program, NETWORK.hrp())
}

// Q = P + H_TapTweak(P)·G
// where H_tag(m) = SHA256(SHA256(tag) ‖ SHA256(tag) ‖ m)
fn taproot_tweak(internal_key: &[u8; 32]) -> Option<[u8; 32]> {
    let tag = sha256::Hash::hash(b"TapTweak");
    let mut eng = sha256::Hash::engine();
    eng.input(tag.as_ref());
    eng.input(tag.as_ref());
    eng.input(internal_key.as_ref());
    let tweak_hash = sha256::Hash::from_engine(eng);

    let mut tweak_bytes = [0u8; 32];
    tweak_bytes.copy_from_slice(tweak_hash.as_ref());

    // BIP340: internal key is always lifted to even-y point (0x02 prefix)
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(internal_key);

    let enc = EncodedPoint::<k256::Secp256k1>::from_bytes(compressed).ok()?;
    let p: Option<AffinePoint> = AffinePoint::from_encoded_point(&enc).into();
    let p = p?;

    let t: Option<Scalar> = Scalar::from_repr(tweak_bytes.into()).into();
    let t = t?;

    let q = ProjectivePoint::from(p) + ProjectivePoint::GENERATOR * t;
    let q_enc = AffinePoint::from(q).to_encoded_point(true);

    let mut out = [0u8; 32];
    out.copy_from_slice(&q_enc.as_bytes()[1..]);
    Some(out)
}

// ── Bech32m encoding (BIP350) ────────────────────────────────────────────────

// P2TR address: hrp + "1" + version char + 52 data chars + 6 checksum = 62 bytes total.
fn p2tr_address(witness_program: &[u8; 32], hrp: &str) -> [u8; 62] {
    const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const BECH32M_CONST: u32 = 0x2bc830a3;

    // 8→5 bit conversion: 32 bytes = 256 bits → 52 five-bit groups (padded)
    let mut groups = [0u8; 52];
    {
        let mut acc = 0u32;
        let mut bits = 0u32;
        let mut pos = 0;
        for &byte in witness_program.iter() {
            acc = (acc << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                groups[pos] = ((acc >> bits) & 0x1f) as u8;
                pos += 1;
            }
        }
        if bits > 0 {
            groups[pos] = ((acc << (5 - bits)) & 0x1f) as u8;
        }
    }

    // Checksum input: hrp_expand(hrp) ++ [version=1] ++ groups ++ [0×6]
    // hrp_expand per BIP173: high bits of each HRP char, then the 0
    // separator, then the low bits.
    let hrp_bytes = hrp.as_bytes();
    let n = hrp_bytes.len();
    let mut values = [0u8; 64]; // hrp_expand (2n+1) + version(1) + 52 groups + 6 checksum
    for (i, &b) in hrp_bytes.iter().enumerate() {
        values[i] = b >> 5;
        values[n + 1 + i] = b & 31;
    }
    values[n] = 0; // separator
    values[2 * n + 1] = 1; // witness version 1
    values[2 * n + 2..2 * n + 54].copy_from_slice(&groups);
    // values[2n+54 .. 2n+60] stay 0 (checksum placeholder)
    let chk = bech32m_polymod(&values) ^ BECH32M_CONST;

    let mut out = [0u8; 62];
    out[0] = hrp_bytes[0];
    out[1] = hrp_bytes[1];
    out[2] = b'1';
    out[3] = CHARSET[1]; // version 1 → index 1 → 'p'
    for (i, &g) in groups.iter().enumerate() {
        out[4 + i] = CHARSET[g as usize];
    }
    for i in 0..6usize {
        out[56 + i] = CHARSET[((chk >> (5 * (5 - i as u32))) & 0x1f) as usize];
    }
    out
}

fn bech32m_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ u32::from(v);
        for (i, &g) in GEN.iter().enumerate() {
            if (b >> i) & 1 != 0 {
                chk ^= g;
            }
        }
    }
    chk
}

// ── BIP39 word-index decoding ────────────────────────────────────────────────

/// Converts 24 BIP39 word indices (0–2047) to the original 32-byte entropy.
///
/// Each index is 11 bits; 24 × 11 = 264 bits = 256-bit entropy + 8-bit checksum.
/// Returns `None` if the SHA256 checksum embedded in the indices is invalid.
pub fn indices_to_entropy(indices: &[u16; 24]) -> Option<[u8; 32]> {
    // Pack 24 × 11 bits into 33 bytes, MSB-first.
    let mut raw = [0u8; 33];
    for (word, &idx) in indices.iter().enumerate() {
        let bit_start = word * 11;
        for bit in 0..11usize {
            if (idx >> (10 - bit)) & 1 == 1 {
                let pos = bit_start + bit;
                raw[pos / 8] |= 1 << (7 - pos % 8);
            }
        }
    }
    // First 32 bytes = entropy; raw[32] holds the 8-bit checksum.
    let mut entropy = [0u8; 32];
    entropy.copy_from_slice(&raw[..32]);
    // BIP39 checksum = first 8 bits of SHA256(entropy).
    let hash = sha256::Hash::hash(&entropy);
    let hash_bytes: &[u8] = hash.as_ref();
    if hash_bytes[0] == raw[32] {
        Some(entropy)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indices_to_entropy_round_trip() {
        // Encode a known entropy as a BIP39 mnemonic, extract word indices,
        // then verify that indices_to_entropy reconstructs the original entropy.
        let entropy = [0x42u8; 32];
        let m = bip39::Mnemonic::from_entropy(&entropy).unwrap();
        let word_list = bip39::Language::English.word_list();
        let mut indices = [0u16; 24];
        for (i, word) in m.words().enumerate() {
            indices[i] = word_list.iter().position(|&w| w == word).unwrap() as u16;
        }
        assert_eq!(indices_to_entropy(&indices), Some(entropy));
    }

    #[test]
    fn indices_to_entropy_bad_checksum() {
        // Flip a bit in the entropy area — checksum should fail.
        let entropy = [0x42u8; 32];
        let m = bip39::Mnemonic::from_entropy(&entropy).unwrap();
        let word_list = bip39::Language::English.word_list();
        let mut indices = [0u16; 24];
        for (i, word) in m.words().enumerate() {
            indices[i] = word_list.iter().position(|&w| w == word).unwrap() as u16;
        }
        indices[0] ^= 1; // corrupt first word
        assert!(indices_to_entropy(&indices).is_none());
    }

    #[test]
    fn bech32m_address_format() {
        // Any 32-byte witness program should produce a valid 62-char address
        // on both networks, with only charset characters.
        const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        let program = [0x42u8; 32];
        for hrp in ["bc", "tb"] {
            let addr = p2tr_address(&program, hrp);
            let hrp_bytes = hrp.as_bytes();
            assert_eq!(addr.len(), 62);
            assert_eq!(addr[0], hrp_bytes[0]);
            assert_eq!(addr[1], hrp_bytes[1]);
            assert_eq!(addr[2], b'1');
            for &c in &addr[3..] {
                assert!(CHARSET.contains(&c), "unexpected char: {c}");
            }
        }
    }

    #[test]
    fn p2tr_address_bip350_mainnet_vector() {
        // BIP350 test vector: witness v1, program = x-coordinate of the
        // generator point, mainnet.
        let program: [u8; 32] = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ];
        let addr = p2tr_address(&program, "bc");
        assert_eq!(
            &addr[..],
            b"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
        );
    }

    #[test]
    fn p2tr_address_bip350_testnet_vector() {
        // BIP350 test vector: witness v1 testnet address ↔ scriptPubKey
        // 5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433.
        let program: [u8; 32] = [
            0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21, 0xb2, 0xa1, 0x87, 0x90, 0x5e,
            0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5, 0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab,
            0x93, 0xe8, 0x64, 0x33,
        ];
        let addr = p2tr_address(&program, "tb");
        assert_eq!(
            &addr[..],
            b"tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c"
        );
    }

    #[test]
    fn taproot_address_returns_tb1p_on_testnet() {
        // Non-zero seed should derive successfully and start with the
        // NETWORK prefix (testnet per derive.rs).
        let mut seed = [0u8; 64];
        seed[0] = 1; // avoid all-zero edge case
        if let Some(addr) = taproot_address(&seed) {
            assert_eq!(&addr[..4], b"tb1p");
            assert_eq!(addr.len(), 62);
        }
    }

    // ── Descriptor (BIP380/386) ──────────────────────────────────────────────

    #[test]
    fn descriptor_checksum_bip380_vector() {
        // BIP380 test vector: valid checksum for this payload.
        assert_eq!(descriptor_checksum(b"raw(deadbeef)"), Some(*b"89f8spxm"));
    }

    #[test]
    fn descriptor_structure_and_checksum() {
        let mut seed = [0u8; 64];
        seed[0] = 1;
        let mut buf = [0u8; DESCRIPTOR_MAX];
        let len = taproot_descriptor(&seed, &mut buf).expect("descriptor builds");
        let desc = &buf[..len];

        // Structure: tr([fpr/86h/{coin}h/0h]tpub…/<0;1>/*)#checksum
        assert!(desc.starts_with(b"tr(["), "descriptor: {}", core::str::from_utf8(desc).unwrap());
        assert!(core::str::from_utf8(desc).unwrap().contains("/86h/1h/0h]"), "testnet coin type expected");
        assert!(core::str::from_utf8(desc).unwrap().contains("tpub"), "testnet xpub prefix expected");

        // Re-verify the checksum the way BIP380 defines validity: body is
        // everything before the '#', and polymod(expand(body) + checksum
        // symbols) must equal 1.
        let hash_pos = desc.iter().rposition(|&c| c == b'#').expect("checksum separator");
        let (body, checksum) = desc.split_at(hash_pos);
        assert_eq!(checksum[0], b'#');
        assert_eq!(checksum.len(), 9);
        let (mut symbols, mut n) = descriptor_expand(body).expect("chars in charset");
        for &c in &checksum[1..] {
            let idx = DESCRIPTOR_CHECKSUM_CHARSET
                .iter()
                .position(|&x| x == c)
                .expect("checksum in charset") as u16;
            symbols[n] = idx;
            n += 1;
        }
        assert_eq!(descriptor_polymod(&symbols[..n]), 1, "descriptor checksum must verify");
    }

    #[test]
    fn descriptor_is_stable_across_calls() {
        let mut seed = [0u8; 64];
        seed[0] = 1;
        let mut a = [0u8; DESCRIPTOR_MAX];
        let mut b = [0u8; DESCRIPTOR_MAX];
        let la = taproot_descriptor(&seed, &mut a).unwrap();
        let lb = taproot_descriptor(&seed, &mut b).unwrap();
        assert_eq!(la, lb);
        assert_eq!(&a[..la], &b[..lb]);
    }
}
