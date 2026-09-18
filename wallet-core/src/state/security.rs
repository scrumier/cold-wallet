//! Le PIN et le chiffrement au repos : compteur d'échecs, KDF lent, AEAD,
//! verrouillage définitif.
//!
//! L'ordre compte et il tient ici d'un bloc : le compteur d'échecs est écrit
//! sur disque *avant* que le PIN soit vérifié, et la phase lente (PBKDF2 +
//! AEAD) est séparée de la phase rapide (comparaison) pour que l'écran puisse
//! afficher « Vérification… » entre les deux.

use crate::crypto::{self, NONCE_LEN, SALT_LEN};
use crate::storage::{encrypt_into_blob, try_decrypt, update_lockout, Secrets, PERSIST_BYTES};

use super::machine::shuffle;
use super::mnemonic::generate_words;
use super::{zero_sensitive, AppState, ColdWallet, PinGate, PIN_MAX_ATTEMPTS};

impl ColdWallet {
    /// Cheap phase of EnterPin resolution. Runs synchronously when the 6th
    /// digit is entered. Side-effects:
    ///   - Write-ahead increment of `failures` on disk (before any check).
    ///   - If the PIN is already known in-memory (in-session prompt), does the
    ///     plain comparison inline and transitions straight to the gate target
    ///     / EnterPin retry / PinLocked.
    ///   - Otherwise (cold-start: PIN must be verified via AEAD decryption),
    ///     parks the state machine in `PinVerifying` and returns. The actual
    ///     KDF + AEAD will run in `process_pending`.
    pub(super) fn begin_enter_pin<F: FnMut(&[u8; PERSIST_BYTES])>(
        &mut self,
        digits:        [u8; 6],
        gate:          PinGate,
        touch_entropy: &[u8; 32],
        persist:       &mut F,
    ) {
        // Write-ahead: bump failures on disk *before* checking. A crash here
        // leaves the counter incremented, so restart cannot rewind the lockout.
        self.failures = self.failures.saturating_add(1);
        if let Some(ref mut img) = self.disk_image {
            update_lockout(img, self.failures, false);
            persist(img);
        }

        if let Some(stored) = self.pin {
            // In-session fast path: plain comparison, resolve immediately.
            let correct = ct_eq_pin(&stored, &digits);
            self.finalize_enter_pin(correct, gate, touch_entropy, persist);
        } else {
            // Cold-start path: AEAD verification is slow — park in PinVerifying
            // and let `process_pending` run the KDF after the UI redraws.
            self.state = AppState::PinVerifying { digits, gate };
        }
    }

    /// Resolves a PIN attempt outcome. Shared by the in-session fast path and
    /// the cold-start KDF path.
    fn finalize_enter_pin<F: FnMut(&[u8; PERSIST_BYTES])>(
        &mut self,
        correct:       bool,
        gate:          PinGate,
        touch_entropy: &[u8; 32],
        persist:       &mut F,
    ) {
        if correct {
            self.failures = 0;
            if let Some(ref mut img) = self.disk_image {
                update_lockout(img, 0, false);
                persist(img);
            }
            self.state = match gate {
                PinGate::Unlock       => AppState::Home,
                PinGate::ShowMnemonic => AppState::ShowMnemonic { page: 0 },
                PinGate::ChangePin    => AppState::SetPin {
                    order: shuffle(touch_entropy),
                    digits: [0u8; 6], len: 0,
                },
            };
        } else if self.failures >= PIN_MAX_ATTEMPTS {
            self.locked = true;
            if let Some(ref mut img) = self.disk_image {
                update_lockout(img, self.failures, true);
                persist(img);
            }
            self.state = AppState::PinLocked;
        } else {
            self.state = AppState::EnterPin {
                order:  shuffle(touch_entropy),
                digits: [0u8; 6], len: 0,
                gate,
            };
        }
    }

    /// Cheap phase of ConfirmPin resolution. Compares the entered digits to
    /// the originally chosen PIN. On mismatch → PinMismatch. On match → parks
    /// in `PinConfirming` for the slow encryption pass.
    pub(super) fn begin_confirm_pin(&mut self, mut pin: [u8; 6], mut digits: [u8; 6]) {
        if !ct_eq_pin(&digits, &pin) {
            self.state = AppState::PinMismatch;
            zero_sensitive(&mut digits);
            zero_sensitive(&mut pin);
            return;
        }
        // digits is Copy — copied into PinConfirming; zero the local copy after.
        self.state = AppState::PinConfirming { new_pin: digits };
        zero_sensitive(&mut digits);
        zero_sensitive(&mut pin);
    }

    /// Runs the deferred slow work when the state machine is parked in
    /// `PinVerifying` or `PinConfirming`. The host (sim / firmware) calls this
    /// AFTER drawing the intermediate spinner screen, so the user sees
    /// "Verifying PIN…" / "Saving wallet…" during the PBKDF2 pass.
    ///
    /// `fresh_entropy` is consumed for shuffling the next PIN pad (verify path)
    /// and for generating fresh salt + nonce (confirm path).
    ///
    /// Returns `true` iff there was pending work to do.
    pub fn process_pending<F>(&mut self, fresh_entropy: [u8; 32], persist: &mut F) -> bool
    where
        F: FnMut(&[u8; PERSIST_BYTES]),
    {
        match self.state {
            AppState::PinVerifying { digits, gate } => {
                self.process_pin_verifying(digits, gate, &fresh_entropy, persist);
                true
            }
            AppState::PinConfirming { new_pin } => {
                self.process_pin_confirming(new_pin, &fresh_entropy, persist);
                true
            }
            _ => false,
        }
    }

    fn process_pin_verifying<F: FnMut(&[u8; PERSIST_BYTES])>(
        &mut self,
        mut digits:    [u8; 6],
        gate:          PinGate,
        fresh_entropy: &[u8; 32],
        persist:       &mut F,
    ) {
        // Cold-start: try to decrypt the disk image with the typed PIN.
        //
        // Security: `key` is derived from the typed PIN and must be zeroed on
        // the failure path so a wrong-PIN guess does not linger on the stack.
        // On success, `key` is moved into `self.enc_key` (no copy remains here).
        let correct = if let Some(ref img) = self.disk_image {
            let mut key = crypto::derive_key(&digits, &self.salt);
            match try_decrypt(img, &key) {
                Ok(secrets) => {
                    self.entropy = secrets.entropy;
                    self.seed    = secrets.seed;
                    self.rebuild_derivations();
                    self.words   = generate_words(&self.entropy);
                    self.pin     = Some(digits);
                    self.enc_key = Some(key);
                    // `key` was moved into `self.enc_key` — no copy remains here.
                    true
                }
                Err(_) => {
                    // Wrong PIN: zero the derived key so it does not linger on
                    // the stack after this scope exits.
                    zero_sensitive(&mut key);
                    false
                }
            }
        } else {
            false
        };

        // digits was Copy'd into self.pin on success; zero the local parameter copy.
        zero_sensitive(&mut digits);

        self.finalize_enter_pin(correct, gate, fresh_entropy, persist);
    }

    fn process_pin_confirming<F: FnMut(&[u8; PERSIST_BYTES])>(
        &mut self,
        mut new_pin:   [u8; 6],
        fresh_entropy: &[u8; 32],
        persist:       &mut F,
    ) {
        let mut salt  = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        salt.copy_from_slice(&fresh_entropy[..SALT_LEN]);
        nonce.copy_from_slice(&fresh_entropy[SALT_LEN..SALT_LEN + NONCE_LEN]);

        // `key` is `[u8; KEY_LEN]` (Copy). It is zeroed on both branches so the
        // PBKDF2-derived bytes don't linger on the stack if encryption fails.
        let mut key = crypto::derive_key(&new_pin, &salt);
        let secrets = Secrets { entropy: self.entropy, seed: self.seed };
        match encrypt_into_blob(&secrets, &salt, &nonce, &key, 0, false) {
            Ok(image) => {
                self.salt       = salt;
                self.enc_key    = Some(key); // key is Copy — local still alive
                zero_sensitive(&mut key);    // zero the local copy
                self.pin        = Some(new_pin);
                self.failures   = 0;
                self.locked     = false;
                self.disk_image = Some(image);
                persist(self.disk_image.as_ref().unwrap());
                self.state = AppState::Home;
            }
            Err(_) => {
                zero_sensitive(&mut key); // zero key — wrong-PIN derived bytes must not linger
                self.state = AppState::PinMismatch;
            }
        }

        // new_pin was Copy'd into self.pin on success; zero the local parameter copy.
        zero_sensitive(&mut new_pin);
    }

    /// True iff the state machine is parked in a deferred-work state and the
    /// caller should redraw, then call `process_pending`.
    pub fn has_pending_work(&self) -> bool {
        matches!(self.state, AppState::PinVerifying { .. } | AppState::PinConfirming { .. })
    }

}

/// Compares two PIN arrays without early exit to avoid timing side channels.
fn ct_eq_pin(a: &[u8; 6], b: &[u8; 6]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..6 { diff |= a[i] ^ b[i]; }
    diff == 0
}
