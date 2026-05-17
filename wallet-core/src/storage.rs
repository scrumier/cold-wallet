/// Persisted wallet state — written to disk by the simulator, read back on next launch.
///
/// Layout (103 bytes):
///   [0..32]   entropy — BIP39 source entropy, so mnemonic can be re-displayed
///   [32..96]  seed    — BIP39 seed (passphrase already baked in)
///   [96..102] pin
///   [102]     version = 1
pub const PERSIST_BYTES: usize = 103;

pub struct PersistedWallet {
    pub entropy: [u8; 32],
    pub seed:    [u8; 64],
    pub pin:     [u8; 6],
}

impl PersistedWallet {
    pub fn to_bytes(&self) -> [u8; PERSIST_BYTES] {
        let mut out = [0u8; PERSIST_BYTES];
        out[0..32].copy_from_slice(&self.entropy);
        out[32..96].copy_from_slice(&self.seed);
        out[96..102].copy_from_slice(&self.pin);
        out[102] = 1;
        out
    }

    /// Returns `None` if the version byte is unknown or if entropy/seed are all-zero.
    pub fn from_bytes(b: &[u8; PERSIST_BYTES]) -> Option<Self> {
        if b[102] != 1 { return None; }
        let mut entropy = [0u8; 32];
        let mut seed    = [0u8; 64];
        let mut pin     = [0u8; 6];
        entropy.copy_from_slice(&b[0..32]);
        seed.copy_from_slice(&b[32..96]);
        pin.copy_from_slice(&b[96..102]);
        if entropy == [0u8; 32] || seed == [0u8; 64] { return None; }
        Some(Self { entropy, seed, pin })
    }
}

impl Drop for PersistedWallet {
    fn drop(&mut self) {
        for b in self.entropy.iter_mut() { unsafe { core::ptr::write_volatile(b, 0); } }
        for b in self.seed.iter_mut()    { unsafe { core::ptr::write_volatile(b, 0); } }
        for b in self.pin.iter_mut()     { unsafe { core::ptr::write_volatile(b, 0); } }
    }
}
