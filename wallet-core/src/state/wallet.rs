//! Ce qui dérive et ce qui signe : adresse, fenêtre de clés, descriptor,
//! chargement d'un PSBT depuis la carte SD, signature BIP340.
//!
//! Appelé par `handle_event` quand la machine a atteint l'état correspondant.

use bip39::Mnemonic;

use crate::base64;
use crate::derive::{own_output_keys, taproot_address, taproot_descriptor};
use crate::psbt::{self, ParsedPsbt, MAX_PSBT_RAW, MAX_SIGNED_RAW};
use crate::signing::sign_psbt;

use super::{AppState, ColdWallet};

impl ColdWallet {
    pub(super) fn derive_address(&mut self, passphrase: &str) {
        if let Ok(m) = Mnemonic::from_entropy(&self.entropy) {
            let mut seed = m.to_seed_normalized(passphrase);
            debug_assert!(taproot_address(&seed).is_some(), "taproot derivation failed");
            if taproot_address(&seed).is_some() {
                self.seed = seed; // seed is Copy — self.seed now holds it
                self.rebuild_derivations();
            }
            // Zero the local copy regardless of derivation success.
            for b in seed.iter_mut() { unsafe { core::ptr::write_volatile(b, 0); } }
        }
    }

    /// Rebuilds everything derived from the seed: receive address, the
    /// derivation-window output keys (F-04) and the BIP386 descriptor.
    /// Called whenever the seed becomes available (setup, restore, unlock).
    pub(super) fn rebuild_derivations(&mut self) {
        self.address = taproot_address(&self.seed).unwrap_or([0u8; 62]);
        self.own_keys = own_output_keys(&self.seed);
        self.descriptor_len = taproot_descriptor(&self.seed, &mut self.descriptor).unwrap_or(0);
    }

    /// Decodes a Base64 PSBT, parses it, and transitions to SignReview on success.
    /// On decode or parse failure stays in SignScan and sets `scan_error_flag = true`
    /// so the draw layer can show a "PSBT rejected — rescan" hint.
    pub(super) fn load_psbt(&mut self, b64: &[u8]) {
        let mut raw = [0u8; MAX_PSBT_RAW];
        let Some(raw_len) = base64::decode(b64, &mut raw) else {
            self.scan_error_flag = true;
            return;
        };
        match ParsedPsbt::parse(&raw[..raw_len]) {
            Ok(parsed) => {
                self.scan_error_flag = false;
                self.psbt            = Some(parsed);
                self.state           = AppState::SignReview;
            }
            Err(_) => {
                self.scan_error_flag = true;
            }
        }
    }

    /// Signs the stored PSBT with our BIP86 key and Base64-encodes the result.
    pub(super) fn do_sign(&mut self, aux_rand: &[u8; 32]) {
        let Some(ref mut psbt) = self.psbt else { return };
        if sign_psbt(psbt, &self.seed, aux_rand).is_err() { return }

        // Re-emit the PSBT with the signatures added. The unsigned tx inside is
        // the one preserved verbatim at parse time (F-02), not a re-serialisation.
        let mut psbt_bin = [0u8; MAX_SIGNED_RAW];
        let Ok(psbt_len) = psbt::encode_signed(psbt, &mut psbt_bin) else { return };

        // Base64-encode for QR display. The buffer capacity derives from
        // MAX_SIGNED_RAW (psbt.rs), so this only fires on an invariant break.
        if psbt_len.div_ceil(3) * 4 > self.signed_psbt_b64.len() {
            return;
        }
        let b64_len = base64::encode(&psbt_bin[..psbt_len], &mut self.signed_psbt_b64);
        self.signed_psbt_b64_len = b64_len;
    }
}
