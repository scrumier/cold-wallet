//! BIP341 Taproot key-path sighash (SIGHASH_ALL = 0x00, no annex).

use bitcoin_hashes::{sha256, HashEngine};

use crate::psbt::ParsedPsbt;

/// Computes the BIP341 Taproot sighash for the given input index.
/// Assumes SIGHASH_ALL (hash_type = 0x00), key-path spend, no annex.
pub fn taproot_sighash(psbt: &ParsedPsbt, input_idx: usize) -> [u8; 32] {
    debug_assert!(input_idx < psbt.input_count);

    // Pre-compute the five aggregated hashes that cover all inputs/outputs.
    let sha_prevouts     = hash_prevouts(psbt);
    let sha_amounts      = hash_amounts(psbt);
    let sha_scriptpubkeys = hash_scriptpubkeys(psbt);
    let sha_sequences    = hash_sequences(psbt);
    let sha_outputs      = hash_outputs(psbt);

    // Build the sighash preimage.
    // Layout (total = 1+1+4+4 + 32×5 + 1+4 = 175 bytes):
    //   epoch(1) hash_type(1) nVersion(4) nLockTime(4)
    //   sha_prevouts(32) sha_amounts(32) sha_scriptpubkeys(32)
    //   sha_sequences(32) sha_outputs(32)
    //   spend_type(1) input_index(4)
    let mut pre = [0u8; 175];
    let mut p   = 0usize;

    pre[p] = 0x00; p += 1; // sighash epoch
    pre[p] = 0x00; p += 1; // hash_type = SIGHASH_ALL
    pre[p..p + 4].copy_from_slice(&(psbt.version as u32).to_le_bytes()); p += 4;
    pre[p..p + 4].copy_from_slice(&psbt.locktime.to_le_bytes());          p += 4;
    pre[p..p + 32].copy_from_slice(&sha_prevouts);       p += 32;
    pre[p..p + 32].copy_from_slice(&sha_amounts);        p += 32;
    pre[p..p + 32].copy_from_slice(&sha_scriptpubkeys);  p += 32;
    pre[p..p + 32].copy_from_slice(&sha_sequences);      p += 32;
    pre[p..p + 32].copy_from_slice(&sha_outputs);        p += 32;
    pre[p] = 0x00; p += 1; // spend_type = key-path, no annex
    pre[p..p + 4].copy_from_slice(&(input_idx as u32).to_le_bytes()); p += 4;

    debug_assert_eq!(p, 175);

    tagged_hash(b"TapSighash", &pre)
}

// ── Tagged SHA256 ─────────────────────────────────────────────────────────────

fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag);
    let mut eng  = sha256::Hash::engine();
    eng.input(tag_hash.as_ref());
    eng.input(tag_hash.as_ref());
    eng.input(data);
    let h = sha256::Hash::from_engine(eng);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_ref());
    out
}

// ── Component hashes ──────────────────────────────────────────────────────────

fn hash_prevouts(psbt: &ParsedPsbt) -> [u8; 32] {
    let mut eng = sha256::Hash::engine();
    for i in 0..psbt.input_count {
        eng.input(&psbt.inputs[i].txid);
        eng.input(&psbt.inputs[i].vout.to_le_bytes());
    }
    to_bytes(sha256::Hash::from_engine(eng))
}

fn hash_amounts(psbt: &ParsedPsbt) -> [u8; 32] {
    let mut eng = sha256::Hash::engine();
    for i in 0..psbt.input_count {
        eng.input(&psbt.inputs[i].amount_sats.to_le_bytes());
    }
    to_bytes(sha256::Hash::from_engine(eng))
}

fn hash_scriptpubkeys(psbt: &ParsedPsbt) -> [u8; 32] {
    let mut eng = sha256::Hash::engine();
    for i in 0..psbt.input_count {
        let len = psbt.inputs[i].script_len;
        push_varint(&mut eng, len as u64);
        eng.input(&psbt.inputs[i].script_pubkey[..len]);
    }
    to_bytes(sha256::Hash::from_engine(eng))
}

fn hash_sequences(psbt: &ParsedPsbt) -> [u8; 32] {
    let mut eng = sha256::Hash::engine();
    for i in 0..psbt.input_count {
        eng.input(&psbt.inputs[i].sequence.to_le_bytes());
    }
    to_bytes(sha256::Hash::from_engine(eng))
}

fn hash_outputs(psbt: &ParsedPsbt) -> [u8; 32] {
    let mut eng = sha256::Hash::engine();
    for i in 0..psbt.output_count {
        eng.input(&psbt.outputs[i].amount_sats.to_le_bytes());
        let len = psbt.outputs[i].script_len;
        push_varint(&mut eng, len as u64);
        eng.input(&psbt.outputs[i].script_pubkey[..len]);
    }
    to_bytes(sha256::Hash::from_engine(eng))
}

fn push_varint(eng: &mut sha256::HashEngine, n: u64) {
    if n < 0xfd {
        eng.input(&[n as u8]);
    } else if n <= 0xffff {
        let v = [0xfd, (n & 0xff) as u8, ((n >> 8) & 0xff) as u8];
        eng.input(&v);
    } else if n <= 0xffff_ffff {
        let mut v = [0u8; 5]; v[0] = 0xfe; v[1..5].copy_from_slice(&(n as u32).to_le_bytes());
        eng.input(&v);
    } else {
        let mut v = [0u8; 9]; v[0] = 0xff; v[1..9].copy_from_slice(&n.to_le_bytes());
        eng.input(&v);
    }
}

fn to_bytes(h: sha256::Hash) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_ref());
    out
}
