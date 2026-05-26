// generic-array 0.x triggers deprecation warnings inside chacha20poly1305 0.10
// (the next major upgrades to generic-array 1.x). Silence module-locally so
// CI's `-D warnings` stays useful for our own code.
#![allow(deprecated)]

//! At-rest encryption primitives for the persisted wallet.
//!
//! Defense-in-depth note: with a 6-digit PIN (10⁶ combinations) and even
//! 600k PBKDF2 iterations, an attacker with disk access can brute-force the
//! PIN offline in a few CPU-days. The cryptographic guarantee here is
//! "opportunistic disk leak no longer reveals the seed directly"; full
//! resistance against a determined attacker requires the hardware-rate-limited
//! secure element on the STM32H747 target.

use bitcoin_hashes::{HashEngine, hmac::HmacEngine, sha256};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce, Tag,
    aead::{AeadInPlace, KeyInit},
};

/// PBKDF2-HMAC-SHA256 iteration count. Above the OWASP 2023 floor (600k).
/// Note: against a 6-digit PIN this only raises the constant factor — it does
/// not change the offline brute-force order of magnitude. The real rate limit
/// is the STM32H747 secure element. See the module-level note above.
pub const PBKDF2_ITERATIONS: u32 = 1_000_000;
pub const SALT_LEN: usize  = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize   = 16;
pub const KEY_LEN: usize   = 32;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CryptoError {
    AeadFailure,
}

/// Derives a 32-byte key from the 6-digit PIN using PBKDF2-HMAC-SHA256.
/// The PIN bytes are treated as raw digits (0..=9), as stored in `ColdWallet`.
pub fn derive_key(pin: &[u8; 6], salt: &[u8; SALT_LEN]) -> [u8; KEY_LEN] {
    pbkdf2_hmac_sha256_32(pin, salt, PBKDF2_ITERATIONS)
}

/// Encrypts `plaintext` in-place. Returns the authentication tag.
/// `plaintext` is overwritten with ciphertext (same length).
/// `aad` is authenticated but not encrypted — used to bind the plaintext
/// header (version + salt) so it cannot be swapped without failing the tag.
pub fn encrypt(
    key:    &[u8; KEY_LEN],
    nonce:  &[u8; NONCE_LEN],
    aad:    &[u8],
    buffer: &mut [u8],
) -> Result<[u8; TAG_LEN], CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, buffer)
        .map_err(|_| CryptoError::AeadFailure)?;
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(tag.as_slice());
    Ok(out)
}

/// Decrypts `buffer` in-place using `tag`. `aad` must match the value passed to
/// `encrypt`. On AEAD failure (wrong key, tampered ciphertext, or mismatched
/// `aad`), `buffer` is left in an unspecified state — the caller must discard it.
pub fn decrypt(
    key:    &[u8; KEY_LEN],
    nonce:  &[u8; NONCE_LEN],
    aad:    &[u8],
    buffer: &mut [u8],
    tag:    &[u8; TAG_LEN],
) -> Result<(), CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(nonce), aad, buffer, Tag::from_slice(tag))
        .map_err(|_| CryptoError::AeadFailure)
}

// ── PBKDF2-HMAC-SHA256 (RFC 2898) ────────────────────────────────────────────

/// Core PBKDF2-HMAC-SHA256 primitive — single output block (32 bytes = T_1).
///
/// Accepts arbitrary-length password and salt so that standard known-answer
/// test vectors (RFC 7914, etc.) can be exercised directly without being
/// constrained to the fixed 6-byte PIN / 16-byte salt of `derive_key`.
///
/// Implements RFC 2898 §5.2 for dkLen = hLen = 32 (block index 1 only):
///   U_1 = HMAC(password, salt || INT(1))
///   U_i = HMAC(password, U_{i-1})   for i = 2..iterations
///   T_1 = U_1 XOR U_2 XOR … XOR U_iterations
fn pbkdf2_hmac_sha256_32(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    // U_1: HMAC(password, salt || INT(1))
    let mut u = {
        let mut eng = HmacEngine::<sha256::HashEngine>::new(password);
        eng.input(salt);
        eng.input(&1u32.to_be_bytes());
        let h = eng.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(h.as_ref());
        out
    };
    let mut t = u;
    // U_2 … U_iterations
    for _ in 1..iterations {
        u = hmac_sha256(password, &u);
        for (a, b) in t.iter_mut().zip(u.iter()) {
            *a ^= *b;
        }
    }
    t
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut eng = HmacEngine::<sha256::HashEngine>::new(key);
    eng.input(data);
    let h = eng.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_ref());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4231 Test Case 1 — verifies the HMAC-SHA256 primitive.
    #[test]
    fn hmac_sha256_rfc4231_tc1() {
        // HMAC-SHA256(key = 0x0b * 20, data = "Hi There")
        // Expected: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
        let h = hmac_sha256(&[0x0b; 20], b"Hi There");
        let want: [u8; 32] = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
            0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
            0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
            0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(h, want);
    }

    // RFC 7914 §11 — genuine PBKDF2-HMAC-SHA256 known-answer test.
    //
    // Vector: PBKDF2-HMAC-SHA256(P="passwd", S="salt", c=1, dkLen=64)
    // Published in RFC 7914 §11 and independently confirmed via:
    //   python3 -c "import hashlib; print(hashlib.pbkdf2_hmac('sha256', b'passwd', b'salt', 1, 32).hex())"
    //   → 55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc
    //
    // dkLen=64 spans two 32-byte output blocks; our function returns T_1 (block
    // index 1), which covers the first 32 bytes and is independent of T_2.
    #[test]
    fn pbkdf2_rfc7914_known_answer() {
        let got = pbkdf2_hmac_sha256_32(b"passwd", b"salt", 1);
        let expected: [u8; 32] = [
            0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f,
            0xec, 0x16, 0x91, 0xc2, 0x25, 0x44, 0xb6, 0x05,
            0xf9, 0x41, 0x85, 0x21, 0x6d, 0xde, 0x04, 0x65,
            0xe6, 0x8b, 0x9d, 0x57, 0xc2, 0x0d, 0xac, 0xbc,
        ];
        assert_eq!(got, expected);
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key   = [0x42u8; KEY_LEN];
        let nonce = [0x07u8; NONCE_LEN];
        let plaintext = b"hello cold wallet";
        let mut buf = [0u8; 17];
        buf.copy_from_slice(plaintext);

        let aad = b"v3-header";
        let tag = encrypt(&key, &nonce, aad, &mut buf).unwrap();
        assert_ne!(&buf[..], plaintext); // ciphertext differs from plaintext

        decrypt(&key, &nonce, aad, &mut buf, &tag).unwrap();
        assert_eq!(&buf[..], plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key   = [0x42u8; KEY_LEN];
        let nonce = [0x07u8; NONCE_LEN];
        let mut buf = [0u8; 16];
        let tag = encrypt(&key, &nonce, b"", &mut buf).unwrap();

        let mut wrong = key; wrong[0] ^= 0xff;
        assert_eq!(decrypt(&wrong, &nonce, b"", &mut buf, &tag), Err(CryptoError::AeadFailure));
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let key   = [0x42u8; KEY_LEN];
        let nonce = [0x07u8; NONCE_LEN];
        let mut buf = [0u8; 16];
        let tag = encrypt(&key, &nonce, b"", &mut buf).unwrap();
        buf[0] ^= 0x01;
        assert_eq!(decrypt(&key, &nonce, b"", &mut buf, &tag), Err(CryptoError::AeadFailure));
    }

    #[test]
    fn decrypt_wrong_aad_fails() {
        // Tampering with the authenticated header (AAD) must fail the tag.
        let key   = [0x42u8; KEY_LEN];
        let nonce = [0x07u8; NONCE_LEN];
        let mut buf = [0u8; 16];
        let tag = encrypt(&key, &nonce, b"header-A", &mut buf).unwrap();
        assert_eq!(decrypt(&key, &nonce, b"header-B", &mut buf, &tag), Err(CryptoError::AeadFailure));
    }

    #[test]
    fn derive_key_deterministic() {
        // Same PIN+salt must produce the same key every time, and a different
        // PIN must produce a different key. Uses low-iteration path via
        // pbkdf2_hmac_sha256_32 directly to keep the test fast.
        let pin  = [1u8, 2, 3, 4, 5, 6];
        let salt = [0xaau8; SALT_LEN];
        let k1 = pbkdf2_hmac_sha256_32(&pin, &salt, 1);
        let k2 = pbkdf2_hmac_sha256_32(&pin, &salt, 1);
        assert_eq!(k1, k2);

        let mut wrong = pin; wrong[0] = 9;
        let k3 = pbkdf2_hmac_sha256_32(&wrong, &salt, 1);
        assert_ne!(k1, k3);
    }
}
