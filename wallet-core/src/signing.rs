//! Derives the BIP86 tweaked signing key and signs all matching PSBT inputs
//! with BIP340 Schnorr + BIP341 key-path sighash.

use bitcoin_hashes::{sha256, HashEngine};
use k256::{
    NonZeroScalar, Scalar,
    elliptic_curve::PrimeField,
    schnorr::SigningKey,
};
use zeroize::Zeroize;
use crate::derive::{tap_keypair, taproot_tweak_pub};
use crate::psbt::ParsedPsbt;
use crate::sighash::taproot_sighash;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SignError {
    KeyDerivation,
    NoMatchingInput,
    /// Input specifies a sighash type other than SIGHASH_ALL (0x00 or 0x01).
    UnsupportedSighash,
    /// Input has no witness UTXO loaded (script_len == 0); cannot commit to amount/scriptPubKey.
    MissingWitnessUtxo,
    /// Input's witness UTXO scriptPubKey is not the P2TR output of our own
    /// tweaked key, even though its `tap_internal_key` matched ours. A correct
    /// PSBT can never trigger this; it means the host supplied a bogus UTXO.
    WitnessProgramMismatch,
}

impl core::fmt::Display for SignError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::KeyDerivation      => f.write_str("key derivation failed"),
            Self::NoMatchingInput    => f.write_str("no input matched the wallet key"),
            Self::UnsupportedSighash => f.write_str("unsupported sighash type (only SIGHASH_ALL accepted)"),
            Self::MissingWitnessUtxo => f.write_str("input is missing witness UTXO data"),
            Self::WitnessProgramMismatch => f.write_str("input UTXO is not our own P2TR output"),
        }
    }
}

/// Signs all PSBT inputs whose `tap_internal_key` matches the wallet's derived key.
/// Sets `tap_key_sig` on each matching input.
/// Returns the number of inputs signed, or an error.
///
/// `aux_rand` is passed to BIP340 `sign_prehash_with_aux_rand` for fault-injection
/// resistance. On the STM32H747 target, supply 32 TRNG bytes. The simulator sources
/// these from the touch-event entropy (`getrandom`). Pass `&[0u8; 32]` only in tests.
pub fn sign_psbt(psbt: &mut ParsedPsbt, seed: &[u8; 64], aux_rand: &[u8; 32]) -> Result<usize, SignError> {
    let (internal_key, mut privkey_bytes) = tap_keypair(seed).ok_or(SignError::KeyDerivation)?;
    let sk = tweaked_signing_key(&privkey_bytes, &internal_key).ok_or(SignError::KeyDerivation)?;
    // Zero the raw private key bytes now that the SigningKey is built.
    for b in privkey_bytes.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0); }
    }

    // The 32-byte witness program that a UTXO we can actually spend must carry.
    let our_output_key = taproot_tweak_pub(&internal_key).ok_or(SignError::KeyDerivation)?;

    let mut count = 0usize;
    for i in 0..psbt.input_count {
        let Some(tap_ik) = psbt.inputs[i].tap_internal_key else { continue };
        if tap_ik != internal_key { continue }

        // Guard: must have witness UTXO loaded to commit to amount/scriptPubKey.
        if psbt.inputs[i].script_len == 0 {
            return Err(SignError::MissingWitnessUtxo);
        }

        // Guard: the witness UTXO must be our own P2TR output. Taproot already
        // commits scriptPubKey + amount into the sighash, so a forged UTXO can
        // only ever yield an unusable signature — but refusing up front keeps us
        // from emitting signatures for inputs we do not actually own.
        let spk = &psbt.inputs[i].script_pubkey[..psbt.inputs[i].script_len];
        if spk.len() != 34 || spk[0] != 0x51 || spk[1] != 0x20 || spk[2..] != our_output_key {
            return Err(SignError::WitnessProgramMismatch);
        }

        // Guard: refuse sighash types other than SIGHASH_ALL (0x00 default or 0x01 explicit).
        match psbt.inputs[i].sighash_type {
            None | Some(0) | Some(1) => {}
            Some(_) => return Err(SignError::UnsupportedSighash),
        }

        let sighash = taproot_sighash(psbt, i);
        let sig_result: Result<k256::schnorr::Signature, _> =
            sk.sign_prehash_with_aux_rand(&sighash, aux_rand);
        if let Ok(sig) = sig_result {
            let bytes: [u8; 64] = sig.to_bytes();
            psbt.inputs[i].tap_key_sig = Some(bytes);
            count += 1;
        }
    }

    if count == 0 { Err(SignError::NoMatchingInput) } else { Ok(count) }
}

// ── Tweaked signing key ───────────────────────────────────────────────────────

/// Computes the BIP341 tweaked private key for key-path spending.
///
/// tweaked = d + H_TapTweak(P_x)  (mod n)
/// where d is the internal private key and P_x is its x-only public key.
///
/// `SigningKey::from(NonZeroScalar)` normalises the key to even y (BIP340).
fn tweaked_signing_key(privkey: &[u8; 32], internal_key: &[u8; 32]) -> Option<SigningKey> {
    // d = internal private key scalar. Marked mut so we can zeroize it before return.
    let d: Option<Scalar> = Scalar::from_repr((*privkey).into()).into();
    let mut d = d?;

    // t = H_TapTweak(x_only_internal_key)
    let tag = sha256::Hash::hash(b"TapTweak");
    let mut eng = sha256::Hash::engine();
    eng.input(tag.as_ref());
    eng.input(tag.as_ref());
    eng.input(internal_key.as_ref());
    let tweak_hash = sha256::Hash::from_engine(eng);
    let mut tweak_bytes = [0u8; 32];
    tweak_bytes.copy_from_slice(tweak_hash.as_ref());

    let t: Option<Scalar> = Scalar::from_repr(tweak_bytes.into()).into();
    let mut t = t?;

    // tweaked = d + t (mod n); NonZeroScalar rejects 0 (negligible probability)
    let tweaked_nz: Option<NonZeroScalar> = NonZeroScalar::new(d + t).into();
    // Zero private scalar and tweak before returning — Scalar is Copy so both
    // locals still live here even though d+t was already consumed above.
    d.zeroize();
    t.zeroize();
    let tweaked_nz = tweaked_nz?;

    // SigningKey::from normalises to even-y point as required by BIP340.
    // SigningKey implements ZeroizeOnDrop.
    Some(SigningKey::from(tweaked_nz))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::taproot_address;
    use crate::psbt::{ParsedPsbt, TxInput, TxOutput};

    fn test_seed() -> [u8; 64] {
        let mut s = [0u8; 64]; s[0] = 1; s
    }

    /// Build a minimal single-input PSBT matching our test seed's address.
    fn make_test_psbt(seed: &[u8; 64]) -> ParsedPsbt {
        let (internal_key, _) = tap_keypair(seed).unwrap();

        // Compute the tweaked output key (= P2TR witness program)
        let addr = taproot_address(seed).unwrap();
        // P2TR scriptPubKey: OP_1 OP_PUSHBYTES_32 <32-byte witness program>
        // We reconstruct witness_program from the bech32m address by decoding,
        // but for the test we can derive it directly from internal_key via a
        // short duplication of the tweak logic.
        let output_key = crate::derive::taproot_tweak_pub(&internal_key).unwrap();
        let mut spk = [0u8; 34];
        spk[0] = 0x51; // OP_1
        spk[1] = 0x20; // OP_PUSHBYTES_32
        spk[2..].copy_from_slice(&output_key);

        let _ = addr; // verified that address is non-empty

        let mut psbt = ParsedPsbt::zero();
        psbt.version = 2;
        psbt.locktime = 0;
        psbt.input_count = 1;
        psbt.inputs[0] = TxInput {
            txid: [0xab; 32],
            vout: 0,
            sequence: 0xffff_ffff,
            amount_sats: 100_000,
            script_pubkey: spk,
            script_len: 34,
            tap_internal_key: Some(internal_key),
            tap_key_sig: None,
            sighash_type: None,
        };
        psbt.output_count = 1;
        psbt.outputs[0] = TxOutput {
            amount_sats: 99_000,
            script_pubkey: spk,
            script_len: 34,
            tap_internal_key: None,
        };
        psbt
    }

    #[test]
    fn signs_matching_input() {
        let seed = test_seed();
        let mut psbt = make_test_psbt(&seed);
        let result = sign_psbt(&mut psbt, &seed, &[0u8; 32]);
        assert!(result.is_ok(), "sign_psbt failed: {result:?}");
        assert_eq!(result.unwrap(), 1);
        assert!(psbt.inputs[0].tap_key_sig.is_some());
        let sig = psbt.inputs[0].tap_key_sig.unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn sign_then_verify() {
        // Signs a PSBT then verifies the BIP340 Schnorr signature with k256's
        // own verifier — proves the full crypto pipeline is mathematically consistent
        // without any network or external tool.
        use k256::schnorr::VerifyingKey;

        let seed = test_seed();
        let (internal_key, _) = tap_keypair(&seed).unwrap();

        // Tweaked output key — this is what goes in the P2TR scriptPubKey.
        let output_key = crate::derive::taproot_tweak_pub(&internal_key).unwrap();
        let vk = VerifyingKey::from_bytes(&output_key).unwrap();

        // Capture the sighash before sign_psbt mutates the PSBT.
        let mut psbt = make_test_psbt(&seed);
        let sighash = crate::sighash::taproot_sighash(&psbt, 0);
        sign_psbt(&mut psbt, &seed, &[0u8; 32]).unwrap();

        let sig_bytes = psbt.inputs[0].tap_key_sig.unwrap();
        let sig = k256::schnorr::Signature::try_from(sig_bytes.as_ref()).unwrap();

        // verify_raw: sighash is the BIP340 message (already hashed by taproot_sighash).
        // Must match sign_prehash_with_aux_rand which also treats the input as pre-hashed.
        vk.verify_raw(&sighash, &sig)
            .expect("BIP340 Schnorr signature failed to verify against tweaked pubkey");
    }

    #[test]
    fn rejects_mismatched_internal_key() {
        let seed = test_seed();
        let mut psbt = make_test_psbt(&seed);
        // Corrupt the tap_internal_key to a different key
        if let Some(ref mut k) = psbt.inputs[0].tap_internal_key {
            k[0] ^= 0xff;
        }
        let result = sign_psbt(&mut psbt, &seed, &[0u8; 32]);
        assert_eq!(result, Err(SignError::NoMatchingInput));
    }

    #[test]
    fn rejects_missing_internal_key() {
        let seed = test_seed();
        let mut psbt = make_test_psbt(&seed);
        psbt.inputs[0].tap_internal_key = None;
        let result = sign_psbt(&mut psbt, &seed, &[0u8; 32]);
        assert_eq!(result, Err(SignError::NoMatchingInput));
    }

    // ── M4 sighash guard tests ────────────────────────────────────────────────

    #[test]
    fn rejects_unsupported_sighash_type() {
        // sighash_type = Some(3) (SIGHASH_SINGLE) must be refused.
        let seed = test_seed();
        let mut psbt = make_test_psbt(&seed);
        psbt.inputs[0].sighash_type = Some(3);
        let result = sign_psbt(&mut psbt, &seed, &[0u8; 32]);
        assert_eq!(result, Err(SignError::UnsupportedSighash));
    }

    #[test]
    fn accepts_sighash_all_explicit() {
        // sighash_type = Some(1) is SIGHASH_ALL explicit — must sign successfully.
        let seed = test_seed();
        let mut psbt = make_test_psbt(&seed);
        psbt.inputs[0].sighash_type = Some(1);
        let result = sign_psbt(&mut psbt, &seed, &[0u8; 32]);
        assert!(result.is_ok(), "expected ok for sighash 1, got {result:?}");
    }

    #[test]
    fn accepts_sighash_none_default() {
        // sighash_type = None (not specified) defaults to SIGHASH_ALL — must sign.
        let seed = test_seed();
        let mut psbt = make_test_psbt(&seed);
        psbt.inputs[0].sighash_type = None;
        let result = sign_psbt(&mut psbt, &seed, &[0u8; 32]);
        assert!(result.is_ok(), "expected ok for sighash None, got {result:?}");
    }

    #[test]
    fn rejects_foreign_witness_program() {
        // tap_internal_key matches ours, but the witness UTXO scriptPubKey is a
        // P2TR output for a different key — must be refused.
        let seed = test_seed();
        let mut psbt = make_test_psbt(&seed);
        psbt.inputs[0].script_pubkey[10] ^= 0xff; // corrupt the witness program
        let result = sign_psbt(&mut psbt, &seed, &[0u8; 32]);
        assert_eq!(result, Err(SignError::WitnessProgramMismatch));
    }

    #[test]
    fn rejects_missing_witness_utxo() {
        // script_len == 0 means no witness UTXO was loaded — must be refused.
        let seed = test_seed();
        let mut psbt = make_test_psbt(&seed);
        psbt.inputs[0].script_len = 0;
        let result = sign_psbt(&mut psbt, &seed, &[0u8; 32]);
        assert_eq!(result, Err(SignError::MissingWitnessUtxo));
    }

    #[test]
    fn signs_multi_input_psbt() {
        // Two inputs both spending our own P2TR UTXO. Both must be signed and
        // independently verified. This exercises the sighash loop and the
        // sha_prevouts / sha_amounts / sha_sequences commitment to all inputs.
        use k256::schnorr::VerifyingKey;

        let seed = test_seed();
        let (internal_key, _) = tap_keypair(&seed).unwrap();
        let output_key = crate::derive::taproot_tweak_pub(&internal_key).unwrap();
        let vk = VerifyingKey::from_bytes(&output_key).unwrap();

        let mut spk = [0u8; 34];
        spk[0] = 0x51; spk[1] = 0x20;
        spk[2..].copy_from_slice(&output_key);

        let mut psbt = ParsedPsbt::zero();
        psbt.version = 2;
        psbt.locktime = 0;
        psbt.input_count = 2;
        psbt.inputs[0] = TxInput {
            txid: [0xaa; 32], vout: 0, sequence: 0xffff_ffff,
            amount_sats: 60_000, script_pubkey: spk, script_len: 34,
            tap_internal_key: Some(internal_key), tap_key_sig: None, sighash_type: None,
        };
        psbt.inputs[1] = TxInput {
            txid: [0xbb; 32], vout: 1, sequence: 0xffff_ffff,
            amount_sats: 40_000, script_pubkey: spk, script_len: 34,
            tap_internal_key: Some(internal_key), tap_key_sig: None, sighash_type: None,
        };
        psbt.output_count = 1;
        psbt.outputs[0] = TxOutput {
            amount_sats: 99_000, script_pubkey: spk, script_len: 34, tap_internal_key: None,
        };

        // Capture sighashes before mutating.
        let sh0 = crate::sighash::taproot_sighash(&psbt, 0);
        let sh1 = crate::sighash::taproot_sighash(&psbt, 1);

        let result = sign_psbt(&mut psbt, &seed, &[0u8; 32]);
        assert!(result.is_ok(), "multi-input sign failed: {result:?}");
        assert_eq!(result.unwrap(), 2);

        // Both sighashes must have been signed and must verify independently.
        for (idx, sh) in [(0, sh0), (1, sh1)] {
            let sig_bytes = psbt.inputs[idx].tap_key_sig.unwrap();
            let sig = k256::schnorr::Signature::try_from(sig_bytes.as_ref()).unwrap();
            vk.verify_raw(&sh, &sig)
                .unwrap_or_else(|_| panic!("sig for input {idx} failed verification"));
        }

        // The two sighashes must differ (they commit to the input index).
        assert_ne!(sh0, sh1, "sighashes for different input indices must differ");
    }

    #[test]
    fn partial_sign_skips_foreign_inputs() {
        // One input ours, one input with a foreign tap_internal_key.
        // sign_psbt must sign exactly 1 and leave the foreign one unsigned.
        let seed = test_seed();
        let (internal_key, _) = tap_keypair(&seed).unwrap();
        let output_key = crate::derive::taproot_tweak_pub(&internal_key).unwrap();

        let mut spk = [0u8; 34];
        spk[0] = 0x51; spk[1] = 0x20;
        spk[2..].copy_from_slice(&output_key);

        // Foreign output key for the second input.
        let foreign_ik = [0xde; 32];
        let foreign_ok = crate::derive::taproot_tweak_pub(&foreign_ik).unwrap();
        let mut foreign_spk = [0u8; 34];
        foreign_spk[0] = 0x51; foreign_spk[1] = 0x20;
        foreign_spk[2..].copy_from_slice(&foreign_ok);

        let mut psbt = ParsedPsbt::zero();
        psbt.version = 2;
        psbt.input_count = 2;
        psbt.inputs[0] = TxInput {
            txid: [0x01; 32], vout: 0, sequence: 0xffff_ffff,
            amount_sats: 50_000, script_pubkey: spk, script_len: 34,
            tap_internal_key: Some(internal_key), tap_key_sig: None, sighash_type: None,
        };
        psbt.inputs[1] = TxInput {
            txid: [0x02; 32], vout: 0, sequence: 0xffff_ffff,
            amount_sats: 50_000, script_pubkey: foreign_spk, script_len: 34,
            tap_internal_key: Some(foreign_ik), tap_key_sig: None, sighash_type: None,
        };
        psbt.output_count = 1;
        psbt.outputs[0] = TxOutput {
            amount_sats: 99_000, script_pubkey: spk, script_len: 34, tap_internal_key: None,
        };

        let result = sign_psbt(&mut psbt, &seed, &[0u8; 32]);
        assert_eq!(result, Ok(1), "should sign exactly 1 matching input");
        assert!(psbt.inputs[0].tap_key_sig.is_some(), "own input must be signed");
        assert!(psbt.inputs[1].tap_key_sig.is_none(), "foreign input must stay unsigned");
    }
}
