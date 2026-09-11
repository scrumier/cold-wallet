//! PSBT v0 (BIP174) parser and encoder for Taproot key-path spends.
//! All data structures are fixed-size and Copy so they live on the stack.
//!
//! All size limits derive from `MAX_PSBT_RAW` (see the `b64_len` helpers and
//! the compile-time asserts below) so the scan buffer, the parser and the
//! signed-output buffer can never disagree silently (F-03).
//!
//! Known limitation (F-02, partially addressed): the unsigned tx is re-emitted
//! byte-for-byte as received (`tx_raw` is preserved in `ParsedPsbt`), but
//! unknown PSBT fields (BIP32 derivations, unknown keys, non-witness UTXOs)
//! are still dropped on re-encode. BIP174 asks a Signer to preserve them.
//!
//! Known limitation (F-06): input amounts come from the host's WITNESS_UTXO
//! and cannot be verified offline. A lying amount yields an unusable signature
//! (Taproot commits the amount into the sighash), never fund loss — but the
//! fee shown on the review screen may be wrong.

pub const MAX_INPUTS:  usize = 5;
pub const MAX_OUTPUTS: usize = 8;
pub const MAX_SPK_LEN: usize = 34; // P2TR scriptPubKey is exactly 34 bytes
pub const MAX_PSBT_RAW: usize = 4096;

/// Base64 length for `n` raw bytes (const-evaluable).
pub const fn b64_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

/// Base64 capacity a scan buffer must carry for a max-size PSBT.
pub const MAX_PSBT_B64: usize = b64_len(MAX_PSBT_RAW);

/// Bytes added to a PSBT per signed input: PSBT_IN_TAP_KEY_SIG is
/// klen(1) + key(1) + vlen(1) + sig(64).
pub const TAP_KEY_SIG_KV: usize = 67;

/// Largest possible re-encoded signed PSBT: the input budget plus the
/// signatures the wallet may add.
pub const MAX_SIGNED_RAW: usize = MAX_PSBT_RAW + MAX_INPUTS * TAP_KEY_SIG_KV;
pub const MAX_SIGNED_B64: usize = b64_len(MAX_SIGNED_RAW);

/// Largest unsigned tx we accept inside the global map. A canonical BIP174
/// unsigned tx has empty scriptSigs, so 5 inputs + 8 outputs fit in ~560
/// bytes; 768 leaves room for multi-byte varints.
pub const MAX_TX_RAW: usize = 768;

const _: () = assert!(
    MAX_TX_RAW >= 4 + 1 + MAX_INPUTS * (32 + 4 + 3 + 4) + 1 + MAX_OUTPUTS * (8 + 3 + MAX_SPK_LEN) + 4,
    "MAX_TX_RAW must fit the worst-case canonical unsigned tx",
);
const _: () = assert!(MAX_SIGNED_RAW >= MAX_PSBT_RAW, "signed budget cannot shrink");
const _: () = assert!(MAX_PSBT_B64 == b64_len(MAX_PSBT_RAW));

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PsbtError {
    BadMagic,
    Truncated,
    TooManyInputs,
    TooManyOutputs,
    ScriptTooLong,
    MissingUnsignedTx,
    OutputBufTooSmall,
    /// The global unsigned tx carries a non-empty scriptSig — BIP174 requires
    /// them empty; re-emitting such a tx verbatim would sign a non-canonical tx.
    NonEmptyScriptSig,
    /// The global unsigned tx exceeds `MAX_TX_RAW`.
    TxTooLarge,
}

// ── Data structures ───────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct TxInput {
    pub txid:             [u8; 32], // little-endian (as in wire format)
    pub vout:             u32,
    pub sequence:         u32,
    /// Amount in satoshis — from PSBT_IN_WITNESS_UTXO.
    pub amount_sats:      u64,
    /// scriptPubKey of the UTXO — from PSBT_IN_WITNESS_UTXO.
    pub script_pubkey:    [u8; MAX_SPK_LEN],
    pub script_len:       usize,
    /// x-only internal key — from PSBT_IN_TAP_INTERNAL_KEY (0x12).
    pub tap_internal_key: Option<[u8; 32]>,
    /// 64-byte Schnorr sig — set by signing.rs.
    pub tap_key_sig:      Option<[u8; 64]>,
    /// SIGHASH_TYPE — from PSBT_IN_SIGHASH_TYPE (0x03), 4-byte LE u32 per BIP174.
    /// None means not specified (treat as SIGHASH_ALL = 0x00).
    pub sighash_type:     Option<u32>,
}

impl TxInput {
    pub const fn zero() -> Self {
        Self {
            txid: [0u8; 32], vout: 0, sequence: 0xffff_ffff,
            amount_sats: 0, script_pubkey: [0u8; MAX_SPK_LEN], script_len: 0,
            tap_internal_key: None, tap_key_sig: None, sighash_type: None,
        }
    }
}

#[derive(Clone, Copy)]
pub struct TxOutput {
    pub amount_sats:   u64,
    pub script_pubkey: [u8; MAX_SPK_LEN],
    pub script_len:    usize,
    /// x-only internal key from PSBT_OUT_TAP_INTERNAL_KEY (0x05). When this
    /// matches the wallet's own internal key, the output is the wallet's own
    /// change. Note: we do NOT rely on this alone — sign_review additionally
    /// verifies by re-deriving the output key from the wallet's seed and
    /// comparing to the scriptPubKey witness program, so a malicious host
    /// cannot disguise change as a send by simply omitting this field.
    pub tap_internal_key: Option<[u8; 32]>,
}

impl TxOutput {
    const fn zero() -> Self {
        Self {
            amount_sats: 0, script_pubkey: [0u8; MAX_SPK_LEN], script_len: 0,
            tap_internal_key: None,
        }
    }
}

#[derive(Clone, Copy)]
pub struct ParsedPsbt {
    pub version:      i32,
    pub locktime:     u32,
    pub inputs:       [TxInput;  MAX_INPUTS],
    pub input_count:  usize,
    pub outputs:      [TxOutput; MAX_OUTPUTS],
    pub output_count: usize,
    /// The global unsigned tx, byte-for-byte as received (F-02): what gets
    /// signed is what was scanned, not a re-serialisation of parsed fields.
    pub tx_raw:       [u8; MAX_TX_RAW],
    pub tx_len:       usize,
}

impl ParsedPsbt {
    pub const fn zero() -> Self {
        Self {
            version: 0, locktime: 0,
            inputs:  [TxInput::zero();  MAX_INPUTS],
            input_count:  0,
            outputs: [TxOutput::zero(); MAX_OUTPUTS],
            output_count: 0,
            tx_raw: [0u8; MAX_TX_RAW],
            tx_len: 0,
        }
    }

    /// Total amount of all inputs.
    ///
    /// Saturating: a malicious PSBT can set each `amount_sats` near `u64::MAX`,
    /// so a plain `.sum()` would panic in debug builds (and silently wrap in
    /// release). Saturating to `u64::MAX` instead keeps the device alive and
    /// surfaces the bogus total as an over-large fee / overflow warning on the
    /// review screen rather than crashing.
    pub fn total_in(&self) -> u64 {
        self.inputs[..self.input_count]
            .iter()
            .fold(0u64, |acc, i| acc.saturating_add(i.amount_sats))
    }

    /// Total amount of all outputs. Saturating for the same reason as `total_in`.
    pub fn total_out(&self) -> u64 {
        self.outputs[..self.output_count]
            .iter()
            .fold(0u64, |acc, o| acc.saturating_add(o.amount_sats))
    }

    /// Miner fee = total_in - total_out.
    pub fn fee(&self) -> u64 {
        self.total_in().saturating_sub(self.total_out())
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

struct Reader<'a> {
    data: &'a [u8],
    pos:  usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self { Self { data, pos: 0 } }

    fn read_byte(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn read_le32(&mut self) -> Option<u32> {
        let b = self.read_bytes(4)?;
        Some(u32::from_le_bytes(b.try_into().ok()?))
    }

    fn read_le64(&mut self) -> Option<u64> {
        let b = self.read_bytes(8)?;
        Some(u64::from_le_bytes(b.try_into().ok()?))
    }

    fn read_varint(&mut self) -> Option<u64> {
        match self.read_byte()? {
            0xfd => {
                let lo = self.read_byte()? as u64;
                let hi = self.read_byte()? as u64;
                Some(lo | (hi << 8))
            }
            0xfe => {
                let b = self.read_bytes(4)?;
                Some(u32::from_le_bytes(b.try_into().ok()?) as u64)
            }
            0xff => {
                let b = self.read_bytes(8)?;
                Some(u64::from_le_bytes(b.try_into().ok()?))
            }
            b => Some(b as u64),
        }
    }

    /// Reads one PSBT key-value pair. Returns `(key, value)` slices, or `None` on end-of-map (key_len=0).
    #[allow(clippy::type_complexity)]
    fn read_kv(&mut self) -> Result<Option<(&'a [u8], &'a [u8])>, PsbtError> {
        let klen = self.read_varint().ok_or(PsbtError::Truncated)? as usize;
        if klen == 0 { return Ok(None); }
        let key   = self.read_bytes(klen).ok_or(PsbtError::Truncated)?;
        let vlen  = self.read_varint().ok_or(PsbtError::Truncated)? as usize;
        let value = self.read_bytes(vlen).ok_or(PsbtError::Truncated)?;
        Ok(Some((key, value)))
    }

}

impl ParsedPsbt {
    pub fn parse(raw: &[u8]) -> Result<Self, PsbtError> {
        let mut r = Reader::new(raw);
        let mut psbt = ParsedPsbt::zero();

        // Magic: 0x70 0x73 0x62 0x74 0xff ("psbt\xff")
        let magic = r.read_bytes(5).ok_or(PsbtError::Truncated)?;
        if magic != b"\x70\x73\x62\x74\xff" {
            return Err(PsbtError::BadMagic);
        }

        // ── Global map ──────────────────────────────────────────────────────
        loop {
            match r.read_kv()? {
                None => return Err(PsbtError::MissingUnsignedTx),
                Some((key, value)) => {
                    if key == [0x00] {
                        // PSBT_GLOBAL_UNSIGNED_TX — preserve verbatim (F-02), parse in place.
                        if value.len() > MAX_TX_RAW { return Err(PsbtError::TxTooLarge); }
                        psbt.tx_raw[..value.len()].copy_from_slice(value);
                        psbt.tx_len = value.len();
                        parse_unsigned_tx(value, &mut psbt)?;
                        break;
                    }
                    // ignore other global keys
                }
            }
        }
        // Drain remaining global map entries
        loop {
            let klen = r.read_varint().ok_or(PsbtError::Truncated)? as usize;
            if klen == 0 { break; }
            r.read_bytes(klen).ok_or(PsbtError::Truncated)?;
            let vlen = r.read_varint().ok_or(PsbtError::Truncated)? as usize;
            r.read_bytes(vlen).ok_or(PsbtError::Truncated)?;
        }

        // ── Per-input maps ──────────────────────────────────────────────────
        for i in 0..psbt.input_count {
            loop {
                match r.read_kv()? {
                    None => break,
                    Some((key, value)) => match key.first() {
                        // PSBT_IN_WITNESS_UTXO = 0x01
                        Some(&0x01) if key.len() == 1 => {
                            parse_witness_utxo(value, &mut psbt.inputs[i])?;
                        }
                        // PSBT_IN_SIGHASH_TYPE = 0x03, value is 4-byte LE u32 (BIP174)
                        Some(&0x03) if key.len() == 1 && value.len() == 4 => {
                            let st = u32::from_le_bytes(value.try_into().unwrap_or([0u8; 4]));
                            psbt.inputs[i].sighash_type = Some(st);
                        }
                        // PSBT_IN_TAP_INTERNAL_KEY = 0x17 (BIP371)
                        Some(&0x17) if key.len() == 1 && value.len() == 32 => {
                            let mut k = [0u8; 32];
                            k.copy_from_slice(value);
                            psbt.inputs[i].tap_internal_key = Some(k);
                        }
                        // PSBT_IN_TAP_KEY_SIG = 0x13 (already-signed input — keep it)
                        Some(&0x13) if key.len() == 1 && value.len() == 64 => {
                            let mut s = [0u8; 64];
                            s.copy_from_slice(value);
                            psbt.inputs[i].tap_key_sig = Some(s);
                        }
                        _ => {} // ignore unknown keys
                    },
                }
            }
        }

        // ── Per-output maps ─────────────────────────────────────────────────
        // We only care about PSBT_OUT_TAP_INTERNAL_KEY (0x05) for change
        // detection. Every other key is ignored.
        for i in 0..psbt.output_count {
            loop {
                match r.read_kv()? {
                    None => break,
                    Some((key, value)) => match key.first() {
                        // PSBT_OUT_TAP_INTERNAL_KEY = 0x05
                        Some(&0x05) if key.len() == 1 && value.len() == 32 => {
                            let mut k = [0u8; 32];
                            k.copy_from_slice(value);
                            psbt.outputs[i].tap_internal_key = Some(k);
                        }
                        _ => {} // ignore
                    },
                }
            }
        }

        Ok(psbt)
    }
}

fn parse_unsigned_tx(tx: &[u8], psbt: &mut ParsedPsbt) -> Result<(), PsbtError> {
    let mut r = Reader::new(tx);

    psbt.version  = r.read_le32().ok_or(PsbtError::Truncated)? as i32;

    let vin_count = r.read_varint().ok_or(PsbtError::Truncated)? as usize;
    if vin_count > MAX_INPUTS { return Err(PsbtError::TooManyInputs); }
    psbt.input_count = vin_count;

    for i in 0..vin_count {
        let txid = r.read_bytes(32).ok_or(PsbtError::Truncated)?;
        psbt.inputs[i].txid.copy_from_slice(txid);
        psbt.inputs[i].vout = r.read_le32().ok_or(PsbtError::Truncated)?;
        let script_len = r.read_varint().ok_or(PsbtError::Truncated)? as usize;
        if script_len > 0 {
            // BIP174: the unsigned tx has empty scriptSigs. Anything else is a
            // non-canonical tx that must never be signed.
            return Err(PsbtError::NonEmptyScriptSig);
        }
        psbt.inputs[i].sequence = r.read_le32().ok_or(PsbtError::Truncated)?;
    }

    let vout_count = r.read_varint().ok_or(PsbtError::Truncated)? as usize;
    if vout_count > MAX_OUTPUTS { return Err(PsbtError::TooManyOutputs); }
    psbt.output_count = vout_count;

    for i in 0..vout_count {
        psbt.outputs[i].amount_sats = r.read_le64().ok_or(PsbtError::Truncated)?;
        let spk_len = r.read_varint().ok_or(PsbtError::Truncated)? as usize;
        if spk_len > MAX_SPK_LEN { return Err(PsbtError::ScriptTooLong); }
        let spk = r.read_bytes(spk_len).ok_or(PsbtError::Truncated)?;
        psbt.outputs[i].script_pubkey[..spk_len].copy_from_slice(spk);
        psbt.outputs[i].script_len = spk_len;
    }

    psbt.locktime = r.read_le32().ok_or(PsbtError::Truncated)?;
    Ok(())
}

fn parse_witness_utxo(value: &[u8], input: &mut TxInput) -> Result<(), PsbtError> {
    let mut r = Reader::new(value);
    input.amount_sats = r.read_le64().ok_or(PsbtError::Truncated)?;
    let spk_len = r.read_varint().ok_or(PsbtError::Truncated)? as usize;
    if spk_len > MAX_SPK_LEN { return Err(PsbtError::ScriptTooLong); }
    let spk = r.read_bytes(spk_len).ok_or(PsbtError::Truncated)?;
    input.script_pubkey[..spk_len].copy_from_slice(spk);
    input.script_len = spk_len;
    Ok(())
}

// ── Encoder ───────────────────────────────────────────────────────────────────

/// Writes the signed PSBT into `out`. Returns byte count, or `Err` if buffer is too small.
///
/// The global unsigned tx is re-emitted byte-for-byte as received (F-02) —
/// the signature commits to exactly the tx that was scanned.
pub fn encode_signed(psbt: &ParsedPsbt, out: &mut [u8]) -> Result<usize, PsbtError> {
    let mut w = Writer { buf: out, pos: 0 };

    // Magic
    w.bytes(b"\x70\x73\x62\x74\xff").ok_or(PsbtError::OutputBufTooSmall)?;

    // Global map: the preserved unsigned tx
    w.psbt_kv(&[0x00], &psbt.tx_raw[..psbt.tx_len]).ok_or(PsbtError::OutputBufTooSmall)?;
    w.byte(0x00).ok_or(PsbtError::OutputBufTooSmall)?; // terminator

    // Per-input maps
    for i in 0..psbt.input_count {
        let inp = &psbt.inputs[i];

        // PSBT_IN_WITNESS_UTXO
        let mut utxo = [0u8; 43]; // 8 (value) + 1 (varint) + 34 (P2TR scriptPubKey)
        utxo[..8].copy_from_slice(&inp.amount_sats.to_le_bytes());
        utxo[8] = inp.script_len as u8;
        utxo[9..9 + inp.script_len].copy_from_slice(&inp.script_pubkey[..inp.script_len]);
        let utxo_len = 9 + inp.script_len;
        w.psbt_kv(&[0x01], &utxo[..utxo_len]).ok_or(PsbtError::OutputBufTooSmall)?;

        // PSBT_IN_TAP_INTERNAL_KEY (BIP371 type 0x17)
        if let Some(ref ik) = inp.tap_internal_key {
            w.psbt_kv(&[0x17], ik.as_ref()).ok_or(PsbtError::OutputBufTooSmall)?;
        }

        // PSBT_IN_TAP_KEY_SIG (set after signing)
        if let Some(ref sig) = inp.tap_key_sig {
            w.psbt_kv(&[0x13], sig.as_ref()).ok_or(PsbtError::OutputBufTooSmall)?;
        }

        w.byte(0x00).ok_or(PsbtError::OutputBufTooSmall)?; // terminator
    }

    // Per-output maps. Preserve PSBT_OUT_TAP_INTERNAL_KEY so downstream
    // wallets/coordinators retain change-output annotations.
    for i in 0..psbt.output_count {
        if let Some(ref ik) = psbt.outputs[i].tap_internal_key {
            w.psbt_kv(&[0x05], ik.as_ref()).ok_or(PsbtError::OutputBufTooSmall)?;
        }
        w.byte(0x00).ok_or(PsbtError::OutputBufTooSmall)?; // terminator
    }

    Ok(w.pos)
}

// ── Writer helper ─────────────────────────────────────────────────────────────

struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    fn byte(&mut self, b: u8) -> Option<()> {
        *self.buf.get_mut(self.pos)? = b;
        self.pos += 1;
        Some(())
    }

    fn bytes(&mut self, bs: &[u8]) -> Option<()> {
        let end = self.pos.checked_add(bs.len())?;
        self.buf.get_mut(self.pos..end)?.copy_from_slice(bs);
        self.pos = end;
        Some(())
    }

    fn varint(&mut self, n: u64) -> Option<()> {
        if n < 0xfd {
            self.byte(n as u8)
        } else if n <= 0xffff {
            self.byte(0xfd)?;
            self.bytes(&(n as u16).to_le_bytes())
        } else if n <= 0xffff_ffff {
            self.byte(0xfe)?;
            self.bytes(&(n as u32).to_le_bytes())
        } else {
            self.byte(0xff)?;
            self.bytes(&n.to_le_bytes())
        }
    }

    fn psbt_kv(&mut self, key: &[u8], value: &[u8]) -> Option<()> {
        self.varint(key.len() as u64)?;
        self.bytes(key)?;
        self.varint(value.len() as u64)?;
        self.bytes(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A malicious PSBT can set every input/output amount near `u64::MAX`.
    /// `total_in`/`total_out` must saturate instead of panicking (debug) or
    /// silently wrapping (release), so the device stays alive and the review
    /// screen surfaces the bogus total rather than crashing.
    #[test]
    fn totals_saturate_instead_of_overflowing() {
        let mut psbt = ParsedPsbt::zero();
        psbt.input_count  = MAX_INPUTS;
        psbt.output_count = MAX_OUTPUTS;
        for i in 0..MAX_INPUTS  { psbt.inputs[i].amount_sats  = u64::MAX; }
        for i in 0..MAX_OUTPUTS { psbt.outputs[i].amount_sats = u64::MAX; }

        // Would panic in debug with a plain `.sum()`; must saturate here.
        assert_eq!(psbt.total_in(),  u64::MAX);
        assert_eq!(psbt.total_out(), u64::MAX);
        // fee already uses saturating_sub; total_out >= total_in ⇒ fee 0.
        assert_eq!(psbt.fee(), 0);
    }

    #[test]
    fn totals_sum_normally_in_range() {
        let mut psbt = ParsedPsbt::zero();
        psbt.input_count  = 2;
        psbt.output_count = 1;
        psbt.inputs[0].amount_sats  = 60_000;
        psbt.inputs[1].amount_sats  = 40_000;
        psbt.outputs[0].amount_sats = 99_000;
        assert_eq!(psbt.total_in(),  100_000);
        assert_eq!(psbt.total_out(), 99_000);
        assert_eq!(psbt.fee(),       1_000);
    }

    // ── F-02: the unsigned tx is preserved verbatim ──────────────────────────

    /// Serialises an unsigned tx with non-default version, sequence and
    /// locktime, so any re-serialisation divergence would show.
    fn build_exotic_tx(out: &mut [u8; 200]) -> usize {
        let mut p = 0usize;
        let mut spk = [0u8; 34];
        spk[0] = 0x51; spk[1] = 0x20; spk[2..].copy_from_slice(&[0x42u8; 32]);

        out[p..p + 4].copy_from_slice(&3u32.to_le_bytes()); p += 4;          // version 3
        out[p] = 1; p += 1;                                                  // 1 input
        out[p..p + 32].copy_from_slice(&[0x11u8; 32]); p += 32;              // txid
        out[p..p + 4].copy_from_slice(&7u32.to_le_bytes()); p += 4;          // vout 7
        out[p] = 0; p += 1;                                                  // empty scriptSig
        out[p..p + 4].copy_from_slice(&0xffff_fffeu32.to_le_bytes()); p += 4;// sequence
        out[p] = 1; p += 1;                                                  // 1 output
        out[p..p + 8].copy_from_slice(&12_345u64.to_le_bytes()); p += 8;     // amount
        out[p] = 34; p += 1;                                                 // spk len
        out[p..p + 34].copy_from_slice(&spk); p += 34;                       // spk
        out[p..p + 4].copy_from_slice(&0x1122_3344u32.to_le_bytes()); p += 4;// locktime
        p
    }

    /// Wraps a raw tx in a minimal PSBT with one WITNESS_UTXO input map.
    fn wrap_tx_in_psbt(tx: &[u8], out: &mut [u8; 1024]) -> usize {
        let mut p = 0usize;
        let put  = |b: &mut [u8; 1024], pos: &mut usize, v: u8| { b[*pos] = v; *pos += 1; };
        let puts = |b: &mut [u8; 1024], pos: &mut usize, s: &[u8]| {
            b[*pos..*pos + s.len()].copy_from_slice(s); *pos += s.len();
        };
        puts(out, &mut p, b"psbt\xff");
        put(out, &mut p, 1);                     // klen 1
        put(out, &mut p, 0x00);                  // PSBT_GLOBAL_UNSIGNED_TX
        put(out, &mut p, tx.len() as u8);        // vlen (tx fits, < 253)
        puts(out, &mut p, tx);
        put(out, &mut p, 0x00);                  // end global map
        put(out, &mut p, 1);                     // klen 1
        put(out, &mut p, 0x01);                  // PSBT_IN_WITNESS_UTXO
        put(out, &mut p, 8 + 1 + 34);            // vlen
        puts(out, &mut p, &12_345u64.to_le_bytes());
        put(out, &mut p, 34);
        puts(out, &mut p, &{
            let mut spk = [0u8; 34];
            spk[0] = 0x51; spk[1] = 0x20; spk[2..].copy_from_slice(&[0x42u8; 32]);
            spk
        });
        put(out, &mut p, 0x00);                  // end input map
        put(out, &mut p, 0x00);                  // empty output map
        p
    }

    #[test]
    fn signed_encode_preserves_tx_verbatim() {
        let mut tx = [0u8; 200];
        let tx_len = build_exotic_tx(&mut tx);

        let mut raw = [0u8; 1024];
        let raw_len = wrap_tx_in_psbt(&tx[..tx_len], &mut raw);

        let parsed = ParsedPsbt::parse(&raw[..raw_len]).expect("valid PSBT");
        assert_eq!(parsed.version, 3);
        assert_eq!(parsed.locktime, 0x1122_3344);
        assert_eq!(parsed.inputs[0].sequence, 0xffff_fffe);

        let mut signed = [0u8; MAX_SIGNED_RAW];
        let signed_len = encode_signed(&parsed, &mut signed).expect("encode fits");

        let reparsed = ParsedPsbt::parse(&signed[..signed_len]).expect("signed PSBT reparses");
        assert_eq!(reparsed.tx_len, tx_len, "tx length preserved");
        assert_eq!(
            &reparsed.tx_raw[..reparsed.tx_len],
            &tx[..tx_len],
            "signed PSBT must carry the original tx byte-for-byte",
        );
    }

    #[test]
    fn rejects_non_empty_script_sig() {
        // BIP174: the unsigned tx has empty scriptSigs. A non-empty one is a
        // non-canonical tx that must never be signed.
        let mut tx = [0u8; 200];
        let mut p = 0usize;
        tx[p..p + 4].copy_from_slice(&2u32.to_le_bytes()); p += 4;   // version
        tx[p] = 1; p += 1;                                           // 1 input
        tx[p..p + 32].copy_from_slice(&[0x11u8; 32]); p += 32;       // txid
        tx[p..p + 4].copy_from_slice(&0u32.to_le_bytes()); p += 4;   // vout
        tx[p] = 1; p += 1;                                           // scriptSig len 1
        tx[p] = 0xaa; p += 1;                                        // scriptSig byte
        tx[p..p + 4].copy_from_slice(&0xffff_ffffu32.to_le_bytes()); p += 4;
        tx[p] = 1; p += 1;                                           // 1 output
        tx[p..p + 8].copy_from_slice(&1_000u64.to_le_bytes()); p += 8;
        tx[p] = 34; p += 1;                                          // spk len
        tx[p] = 0x51; p += 1; tx[p] = 0x20; p += 1;                  // P2TR prefix
        tx[p..p + 32].copy_from_slice(&[0x42u8; 32]); p += 32;       // program
        tx[p..p + 4].copy_from_slice(&0u32.to_le_bytes()); p += 4;   // locktime

        let mut raw = [0u8; 1024];
        let raw_len = wrap_tx_in_psbt(&tx[..p], &mut raw);
        assert!(matches!(
            ParsedPsbt::parse(&raw[..raw_len]),
            Err(PsbtError::NonEmptyScriptSig)
        ));
    }

    #[test]
    fn parse_reads_tap_internal_key_bip371() {
        // BIP371 : PSBT_IN_TAP_INTERNAL_KEY est 0x17, pas 0x12. Reproduit le
        // PSBT réel de bdk/Sparrow : sans ce champ lu, le signer ne reconnaît
        // aucun input (bug trouvé au jalon testnet).
        let mut tx = [0u8; 200];
        let tx_len = build_exotic_tx(&mut tx);

        let mut raw = [0u8; 1024];
        let mut p = 0usize;
        let put  = |b: &mut [u8; 1024], pos: &mut usize, v: u8| { b[*pos] = v; *pos += 1; };
        let puts = |b: &mut [u8; 1024], pos: &mut usize, s: &[u8]| {
            b[*pos..*pos + s.len()].copy_from_slice(s);
            *pos += s.len();
        };

        puts(&mut raw, &mut p, b"psbt\xff");
        put(&mut raw, &mut p, 1);
        put(&mut raw, &mut p, 0x00);
        put(&mut raw, &mut p, tx_len as u8);
        puts(&mut raw, &mut p, &tx[..tx_len]);
        put(&mut raw, &mut p, 0x00); // fin global map

        // input 0 : WITNESS_UTXO + TAP_INTERNAL_KEY (0x17)
        put(&mut raw, &mut p, 1);
        put(&mut raw, &mut p, 0x01);
        put(&mut raw, &mut p, 8 + 1 + 34);
        puts(&mut raw, &mut p, &12_345u64.to_le_bytes());
        put(&mut raw, &mut p, 34);
        puts(&mut raw, &mut p, &{
            let mut spk = [0u8; 34];
            spk[0] = 0x51; spk[1] = 0x20;
            spk[2..].copy_from_slice(&[0x42u8; 32]);
            spk
        });
        put(&mut raw, &mut p, 1);
        put(&mut raw, &mut p, 0x17);
        put(&mut raw, &mut p, 32);
        puts(&mut raw, &mut p, &[0x5au8; 32]);
        put(&mut raw, &mut p, 0x00); // fin input map
        put(&mut raw, &mut p, 0x00); // output map vide

        let parsed = ParsedPsbt::parse(&raw[..p]).expect("PSBT avec 0x17 doit parser");
        assert_eq!(
            parsed.inputs[0].tap_internal_key,
            Some([0x5au8; 32]),
            "0x17 doit être lu comme tap_internal_key"
        );
    }
}
