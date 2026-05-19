//! PSBT v0 (BIP174) parser and encoder for Taproot key-path spends.
//! All data structures are fixed-size and Copy so they live on the stack.

pub const MAX_INPUTS:  usize = 5;
pub const MAX_OUTPUTS: usize = 8;
pub const MAX_SPK_LEN: usize = 34; // P2TR scriptPubKey is exactly 34 bytes
pub const MAX_PSBT_RAW: usize = 2048;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PsbtError {
    BadMagic,
    Truncated,
    TooManyInputs,
    TooManyOutputs,
    ScriptTooLong,
    MissingUnsignedTx,
    InputCountMismatch,
    OutputCountMismatch,
    OutputBufTooSmall,
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
}

impl TxInput {
    const fn zero() -> Self {
        Self {
            txid: [0u8; 32], vout: 0, sequence: 0xffff_ffff,
            amount_sats: 0, script_pubkey: [0u8; MAX_SPK_LEN], script_len: 0,
            tap_internal_key: None, tap_key_sig: None,
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
}

impl ParsedPsbt {
    pub const fn zero() -> Self {
        Self {
            version: 0, locktime: 0,
            inputs:  [TxInput::zero();  MAX_INPUTS],
            input_count:  0,
            outputs: [TxOutput::zero(); MAX_OUTPUTS],
            output_count: 0,
        }
    }

    /// Total amount of all inputs.
    pub fn total_in(&self) -> u64 {
        self.inputs[..self.input_count].iter().map(|i| i.amount_sats).sum()
    }

    /// Total amount of all outputs.
    pub fn total_out(&self) -> u64 {
        self.outputs[..self.output_count].iter().map(|o| o.amount_sats).sum()
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
        let s = self.data.get(self.pos..self.pos + n)?;
        self.pos += n;
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
        let tx_start;
        let tx_end;
        loop {
            match r.read_kv()? {
                None => return Err(PsbtError::MissingUnsignedTx),
                Some((key, value)) => {
                    if key == [0x00] {
                        // PSBT_GLOBAL_UNSIGNED_TX — parse it in place
                        tx_start = r.pos - value.len();
                        let _ = tx_start; // used below
                        parse_unsigned_tx(value, &mut psbt)?;
                        tx_end = r.pos;
                        let _ = tx_end;
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
                        // PSBT_IN_TAP_INTERNAL_KEY = 0x12
                        Some(&0x12) if key.len() == 1 && value.len() == 32 => {
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
        if script_len > 0 { r.read_bytes(script_len).ok_or(PsbtError::Truncated)?; }
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
pub fn encode_signed(psbt: &ParsedPsbt, tx_raw: &[u8], out: &mut [u8]) -> Result<usize, PsbtError> {
    let mut w = Writer { buf: out, pos: 0 };

    // Magic
    w.bytes(b"\x70\x73\x62\x74\xff").ok_or(PsbtError::OutputBufTooSmall)?;

    // Global map: unsigned tx
    w.psbt_kv(&[0x00], tx_raw).ok_or(PsbtError::OutputBufTooSmall)?;
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

        // PSBT_IN_TAP_INTERNAL_KEY
        if let Some(ref ik) = inp.tap_internal_key {
            w.psbt_kv(&[0x12], ik.as_ref()).ok_or(PsbtError::OutputBufTooSmall)?;
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

/// Serialises the unsigned transaction from a `ParsedPsbt` back to wire format.
pub fn serialize_unsigned_tx(psbt: &ParsedPsbt, out: &mut [u8]) -> Option<usize> {
    let mut w = Writer { buf: out, pos: 0 };

    w.le32(psbt.version as u32)?;
    w.varint(psbt.input_count as u64)?;
    for i in 0..psbt.input_count {
        let inp = &psbt.inputs[i];
        w.bytes(&inp.txid)?;
        w.le32(inp.vout)?;
        w.byte(0x00)?;                  // script_sig_len = 0 (unsigned)
        w.le32(inp.sequence)?;
    }
    w.varint(psbt.output_count as u64)?;
    for i in 0..psbt.output_count {
        let out_i = &psbt.outputs[i];
        w.le64(out_i.amount_sats)?;
        w.varint(out_i.script_len as u64)?;
        w.bytes(&out_i.script_pubkey[..out_i.script_len])?;
    }
    w.le32(psbt.locktime)?;

    Some(w.pos)
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
        let end = self.pos + bs.len();
        self.buf.get_mut(self.pos..end)?.copy_from_slice(bs);
        self.pos = end;
        Some(())
    }

    fn le32(&mut self, v: u32) -> Option<()> { self.bytes(&v.to_le_bytes()) }
    fn le64(&mut self, v: u64) -> Option<()> { self.bytes(&v.to_le_bytes()) }

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
