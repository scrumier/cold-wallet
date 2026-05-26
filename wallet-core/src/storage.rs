//! On-disk persisted wallet (format v3).
//!
//! Layout (143 bytes):
//! ```text
//!   [0]       version          = 3
//!   [1]       failures         (plaintext — used for lockout enforcement before
//!                                any decryption attempt)
//!   [2]       locked           (0/1)
//!   [3..19]   salt             (16 bytes, generated at wallet creation)
//!   [19..31]  nonce            (12 bytes, fresh on every re-encrypt)
//!   [31..127] ciphertext       (96 bytes = entropy[32] ‖ seed[64])
//!   [127..143] tag             (Poly1305, 16 bytes)
//! ```
//!
//! The PIN itself is never stored. The ability to successfully decrypt the
//! ciphertext (i.e. the AEAD tag verifies) IS the proof of knowing the PIN.
//! The plaintext lockout fields are written *before* any decryption attempt
//! (write-ahead) so that a power-cut between increment and check cannot reset
//! the failure counter.
//!
//! v3 binds the version byte + salt as AEAD additional data (see `build_aad`),
//! so a disk attacker cannot swap the salt or downgrade the version without
//! failing the tag. v2 blobs (empty AAD) are rejected as `BadVersion`; there is
//! no in-place migration because re-encryption requires the PIN — the user
//! re-runs setup or restores from the 24-word backup.
//!
//! Migration from v1 (unencrypted 103-byte format) is handled at the call site
//! (wallet-sim) using [`Secrets`] + [`encrypt_into_blob`].

use crate::crypto::{self, CryptoError, KEY_LEN, NONCE_LEN, SALT_LEN, TAG_LEN};

pub const VERSION_V3:   u8    = 3;
pub const PERSIST_BYTES: usize = 143;

/// Bytes of the plaintext header that are authenticated as AEAD additional data:
/// version byte + salt. Binding these means a disk attacker cannot swap the salt
/// or downgrade the version without failing the Poly1305 tag. The lockout fields
/// (failures/locked) are deliberately excluded — they change via `update_lockout`
/// without re-encryption, so they cannot be covered by the ciphertext's tag.
const AAD_LEN: usize = 1 + SALT_LEN;

fn build_aad(version: u8, salt: &[u8; SALT_LEN]) -> [u8; AAD_LEN] {
    let mut aad = [0u8; AAD_LEN];
    aad[0] = version;
    aad[1..].copy_from_slice(salt);
    aad
}

const HDR_VERSION_OFF:  usize = 0;
const HDR_FAILURES_OFF: usize = 1;
const HDR_LOCKED_OFF:   usize = 2;
const HDR_SALT_OFF:     usize = 3;
const NONCE_OFF:        usize = HDR_SALT_OFF + SALT_LEN;          // 19
const CIPHER_OFF:       usize = NONCE_OFF + NONCE_LEN;            // 31
const CIPHER_LEN:       usize = 32 /*entropy*/ + 64 /*seed*/;     // 96
const TAG_OFF:          usize = CIPHER_OFF + CIPHER_LEN;          // 127
const _: () = assert!(TAG_OFF + TAG_LEN == PERSIST_BYTES);

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DiskError {
    BadVersion,
    AeadFailure,
}

impl From<CryptoError> for DiskError {
    fn from(_: CryptoError) -> Self { DiskError::AeadFailure }
}

/// Decrypted secrets. Constructible only by successful AEAD decryption or by
/// the wallet itself during setup. Zeroed on drop.
pub struct Secrets {
    pub entropy: [u8; 32],
    pub seed:    [u8; 64],
}

impl Drop for Secrets {
    fn drop(&mut self) {
        for b in self.entropy.iter_mut() { unsafe { core::ptr::write_volatile(b, 0); } }
        for b in self.seed.iter_mut()    { unsafe { core::ptr::write_volatile(b, 0); } }
    }
}

/// Plaintext header — readable without the PIN.
#[derive(Debug, Clone, Copy)]
pub struct DiskHeader {
    pub failures: u8,
    pub locked:   bool,
    pub salt:     [u8; SALT_LEN],
}

impl DiskHeader {
    /// Validates the version byte and extracts the header fields.
    pub fn parse(blob: &[u8; PERSIST_BYTES]) -> Result<Self, DiskError> {
        if blob[HDR_VERSION_OFF] != VERSION_V3 { return Err(DiskError::BadVersion); }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&blob[HDR_SALT_OFF..HDR_SALT_OFF + SALT_LEN]);
        Ok(Self {
            failures: blob[HDR_FAILURES_OFF],
            locked:   blob[HDR_LOCKED_OFF] != 0,
            salt,
        })
    }
}

/// Attempts to decrypt the blob with the given derived key.
/// On AEAD failure (wrong PIN or tampered file), returns `AeadFailure` —
/// the caller should treat this as a wrong-PIN attempt.
pub fn try_decrypt(blob: &[u8; PERSIST_BYTES], key: &[u8; KEY_LEN]) -> Result<Secrets, DiskError> {
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob[NONCE_OFF..NONCE_OFF + NONCE_LEN]);

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&blob[HDR_SALT_OFF..HDR_SALT_OFF + SALT_LEN]);
    let aad = build_aad(blob[HDR_VERSION_OFF], &salt);

    let mut buf = [0u8; CIPHER_LEN];
    buf.copy_from_slice(&blob[CIPHER_OFF..CIPHER_OFF + CIPHER_LEN]);

    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&blob[TAG_OFF..TAG_OFF + TAG_LEN]);

    let result = crypto::decrypt(key, &nonce, &aad, &mut buf, &tag);

    let secrets = result.map(|()| {
        let mut entropy = [0u8; 32];
        let mut seed    = [0u8; 64];
        entropy.copy_from_slice(&buf[..32]);
        seed.copy_from_slice(&buf[32..]);
        Secrets { entropy, seed }
    });

    // Wipe the working buffer on every path — on AEAD failure it holds the
    // (garbage) decrypted-with-wrong-key bytes, but we zero it regardless.
    for b in buf.iter_mut() { unsafe { core::ptr::write_volatile(b, 0); } }
    Ok(secrets?)
}

/// Encrypts secrets and assembles a complete v3 disk image.
pub fn encrypt_into_blob(
    secrets:  &Secrets,
    salt:     &[u8; SALT_LEN],
    nonce:    &[u8; NONCE_LEN],
    key:      &[u8; KEY_LEN],
    failures: u8,
    locked:   bool,
) -> Result<[u8; PERSIST_BYTES], DiskError> {
    let mut buf = [0u8; CIPHER_LEN];
    buf[..32].copy_from_slice(&secrets.entropy);
    buf[32..].copy_from_slice(&secrets.seed);

    let aad = build_aad(VERSION_V3, salt);
    let tag = crypto::encrypt(key, nonce, &aad, &mut buf)?;

    let mut out = [0u8; PERSIST_BYTES];
    out[HDR_VERSION_OFF]  = VERSION_V3;
    out[HDR_FAILURES_OFF] = failures;
    out[HDR_LOCKED_OFF]   = u8::from(locked);
    out[HDR_SALT_OFF..HDR_SALT_OFF + SALT_LEN].copy_from_slice(salt);
    out[NONCE_OFF..NONCE_OFF + NONCE_LEN].copy_from_slice(nonce);
    out[CIPHER_OFF..CIPHER_OFF + CIPHER_LEN].copy_from_slice(&buf);
    out[TAG_OFF..TAG_OFF + TAG_LEN].copy_from_slice(&tag);

    for b in buf.iter_mut() { unsafe { core::ptr::write_volatile(b, 0); } }
    Ok(out)
}

/// Updates only the plaintext lockout fields of an existing blob.
/// Used for write-ahead persistence on a PIN attempt — the ciphertext is
/// unchanged, so this is safe to do without the encryption key.
pub fn update_lockout(blob: &mut [u8; PERSIST_BYTES], failures: u8, locked: bool) {
    blob[HDR_FAILURES_OFF] = failures;
    blob[HDR_LOCKED_OFF]   = u8::from(locked);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_secrets() -> Secrets {
        let mut entropy = [0u8; 32];
        let mut seed    = [0u8; 64];
        for (i, b) in entropy.iter_mut().enumerate() { *b = i as u8; }
        for (i, b) in seed.iter_mut().enumerate()    { *b = (i + 100) as u8; }
        Secrets { entropy, seed }
    }

    #[test]
    fn encrypt_then_decrypt() {
        let s     = dummy_secrets();
        let salt  = [0xaau8; SALT_LEN];
        let nonce = [0xbbu8; NONCE_LEN];
        let key   = [0xccu8; KEY_LEN];

        let blob = encrypt_into_blob(&s, &salt, &nonce, &key, 0, false).unwrap();
        assert_eq!(blob[0], VERSION_V3);

        let hdr = DiskHeader::parse(&blob).unwrap();
        assert_eq!(hdr.failures, 0);
        assert!(!hdr.locked);
        assert_eq!(hdr.salt, salt);

        let s2 = try_decrypt(&blob, &key).unwrap();
        assert_eq!(s2.entropy, s.entropy);
        assert_eq!(s2.seed,    s.seed);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let s     = dummy_secrets();
        let salt  = [0xaau8; SALT_LEN];
        let nonce = [0xbbu8; NONCE_LEN];
        let key   = [0xccu8; KEY_LEN];

        let blob = encrypt_into_blob(&s, &salt, &nonce, &key, 0, false).unwrap();
        let mut wrong = key; wrong[0] ^= 0xff;
        assert!(matches!(try_decrypt(&blob, &wrong), Err(DiskError::AeadFailure)));
    }

    #[test]
    fn header_update_preserves_ciphertext() {
        let s     = dummy_secrets();
        let salt  = [0xaau8; SALT_LEN];
        let nonce = [0xbbu8; NONCE_LEN];
        let key   = [0xccu8; KEY_LEN];

        let mut blob = encrypt_into_blob(&s, &salt, &nonce, &key, 0, false).unwrap();
        let ciphertext_before = {
            let mut copy = [0u8; CIPHER_LEN + TAG_LEN];
            copy.copy_from_slice(&blob[CIPHER_OFF..PERSIST_BYTES]);
            copy
        };

        update_lockout(&mut blob, 2, false);

        // Header reflects the new values.
        let hdr = DiskHeader::parse(&blob).unwrap();
        assert_eq!(hdr.failures, 2);

        // Ciphertext bytes were not touched — still decrypts to the same secrets.
        assert_eq!(&blob[CIPHER_OFF..PERSIST_BYTES], &ciphertext_before[..]);
        let s2 = try_decrypt(&blob, &key).unwrap();
        assert_eq!(s2.entropy, s.entropy);
    }

    #[test]
    fn bad_version_rejected() {
        let mut blob = [0u8; PERSIST_BYTES];
        blob[0] = 1;
        assert!(matches!(DiskHeader::parse(&blob), Err(DiskError::BadVersion)));
    }
}
