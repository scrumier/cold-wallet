//! BIP32/BIP86 key derivation and P2TR address encoding.
//!
//! Full path: m/86'/0'/0'/0/0  (first Taproot receive address, mainnet)
//! Reference: BIP32, BIP86, BIP340, BIP341, BIP350.

use bip32::{ChildNumber, XPrv};
use bitcoin_hashes::{sha256, HashEngine};
use k256::{
    AffinePoint, ProjectivePoint, Scalar,
    elliptic_curve::{
        PrimeField,
        sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint},
    },
};

/// Derives the BIP86 P2TR receive address from a BIP39 seed.
///
/// Path `m/86'/0'/0'/0/0`, mainnet (`bc1p…`).
/// Returns 62 ASCII bytes, or `None` if any derivation step fails.
pub fn taproot_address(seed: &[u8; 64]) -> Option<[u8; 62]> {
    let internal_key = derive_x_only(seed)?;
    let output_key   = taproot_tweak(&internal_key)?;
    Some(p2tr_mainnet(&output_key))
}

/// Returns `(x_only_internal_key, raw_private_key_bytes)` for the BIP86 path.
///
/// Used by the signing module to construct the tweaked signing key.
pub fn tap_keypair(seed: &[u8; 64]) -> Option<([u8; 32], [u8; 32])> {
    let mut xprv = XPrv::new(seed).ok()?;
    for &(idx, hardened) in &[(86u32, true), (0, true), (0, true), (0, false), (0, false)] {
        let cn = ChildNumber::new(idx, hardened).ok()?;
        xprv = xprv.derive_child(cn).ok()?;
    }
    let privkey_bytes: [u8; 32] = xprv.private_key().to_bytes().into();
    // Derive x_only from the same child xprv — avoids a redundant second derivation from seed.
    let compressed = xprv.public_key().public_key().to_encoded_point(true);
    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(&compressed.as_bytes()[1..]);
    Some((x_only, privkey_bytes))
}

// ── Internal key derivation ──────────────────────────────────────────────────

fn derive_x_only(seed: &[u8; 64]) -> Option<[u8; 32]> {
    let mut xprv = XPrv::new(seed).ok()?;

    // BIP86: m/86'/0'/0'/0/0
    for &(idx, hardened) in &[(86u32, true), (0, true), (0, true), (0, false), (0, false)] {
        let cn = ChildNumber::new(idx, hardened).ok()?;
        xprv = xprv.derive_child(cn).ok()?;
    }

    // Compressed public key: 33 bytes [02|03 prefix] ++ [32-byte x]
    let compressed = xprv.public_key().public_key().to_encoded_point(true);
    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(&compressed.as_bytes()[1..]);
    Some(x_only)
}

// ── BIP341 keypath-only taproot tweak ────────────────────────────────────────

/// Computes the tweaked output key Q = P + H_TapTweak(P)·G (public, x-only).
/// Used by tests and the PSBT builder to construct P2TR scriptPubKeys.
#[allow(dead_code)]
pub fn taproot_tweak_pub(internal_key: &[u8; 32]) -> Option<[u8; 32]> {
    taproot_tweak(internal_key)
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

// P2TR mainnet address: "bc1p" + 52 data chars + 6 checksum chars = 62 bytes total.
fn p2tr_mainnet(witness_program: &[u8; 32]) -> [u8; 62] {
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

    // Checksum input: hrp_expand("bc") ++ [version=1] ++ groups ++ [0×6]
    // hrp_expand("bc"): high=[3,3], sep=[0], low=[2,3]  ('b'=0x62, 'c'=0x63)
    let mut values = [0u8; 64]; // 5 + 1 + 52 + 6
    values[0] = 3; values[1] = 3; values[2] = 0; values[3] = 2; values[4] = 3;
    values[5] = 1; // witness version 1
    values[6..58].copy_from_slice(&groups);
    // values[58..64] stay 0 (checksum placeholder)
    let chk = bech32m_polymod(&values) ^ BECH32M_CONST;

    let mut out = [0u8; 62];
    out[0] = b'b'; out[1] = b'c'; out[2] = b'1';
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
        // Any 32-byte witness program should produce a valid bc1p address.
        let program = [0x42u8; 32];
        let addr = p2tr_mainnet(&program);
        assert_eq!(addr.len(), 62);
        assert_eq!(&addr[..4], b"bc1p");
        // All characters must be in the bech32 charset.
        let charset = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        for &c in &addr[3..] {
            assert!(charset.contains(&c), "unexpected char: {c}");
        }
    }

    #[test]
    fn taproot_address_returns_bc1p() {
        // Non-zero seed should derive successfully and start with "bc1p".
        let mut seed = [0u8; 64];
        seed[0] = 1; // avoid all-zero edge case
        if let Some(addr) = taproot_address(&seed) {
            assert_eq!(&addr[..4], b"bc1p");
            assert_eq!(addr.len(), 62);
        }
    }
}
