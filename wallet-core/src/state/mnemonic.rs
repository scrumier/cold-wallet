//! La saisie de la mnémonique : recherche par préfixe dans la wordlist BIP39,
//! génération des 24 mots depuis l'entropie, hit-test de la bande de
//! suggestions affichée au-dessus du clavier.

use bip39::Mnemonic;

use crate::layout::*;

use super::machine::in_rect;

/// Returns up to 3 BIP39 word indices that start with the given prefix.
/// Returns all-None if fewer than 1 character has been typed.
pub(crate) fn find_matches(buf: &[u8; 8], buf_len: u8) -> [Option<u16>; 3] {
    if buf_len == 0 {
        return [None; 3];
    }
    let prefix = core::str::from_utf8(&buf[..buf_len as usize]).unwrap_or("");
    let word_list = bip39::Language::English.word_list();
    let mut out = [None; 3];
    let mut count = 0usize;
    for (i, &word) in word_list.iter().enumerate() {
        if word.starts_with(prefix) {
            out[count] = Some(i as u16);
            count += 1;
            if count == 3 { break; }
        }
    }
    out
}

pub(super) fn tapped_suggestion(x: i32, y: i32, matches: [Option<u16>; 3]) -> Option<u16> {
    let xs = [RESTORE_SUGGEST_X0, RESTORE_SUGGEST_X1, RESTORE_SUGGEST_X2];
    for (i, &sx) in xs.iter().enumerate() {
        if in_rect(x, y, sx, RESTORE_SUGGEST_Y, RESTORE_SUGGEST_W, RESTORE_SUGGEST_H) {
            return matches[i];
        }
    }
    None
}

pub(super) fn generate_words(entropy: &[u8; 32]) -> [&'static str; 24] {
    let mut words = [""; 24];
    if let Ok(m) = Mnemonic::from_entropy(entropy) {
        for (i, w) in m.words().enumerate() {
            if i >= 24 { break; }
            words[i] = w;
        }
    }
    words
}
