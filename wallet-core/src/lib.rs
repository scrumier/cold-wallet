#![cfg_attr(not(feature = "std"), no_std)]

mod base64;
mod crypto;
mod derive;
mod draw;
mod keyboard;
mod layout;
mod psbt;
mod sighash;
mod signing;
mod state;
pub mod storage;

use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::DrawTarget;

pub use state::{AppState, ColdWallet, WalletEvent};
pub use storage::{DiskHeader, DiskError, Secrets, PERSIST_BYTES, VERSION_V3,
                  encrypt_into_blob, try_decrypt};
pub use crypto::{derive_key, KEY_LEN, NONCE_LEN, SALT_LEN};

pub fn draw_ui<D>(display: &mut D, wallet: &ColdWallet) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    draw::draw_ui(
        display,
        wallet.get_state(),
        wallet.mnemonic_words(),
        wallet.receive_address(),
        wallet.current_psbt(),
        wallet.signed_psbt_b64(),
        wallet.tap_output_key(),
        wallet.scan_error(),
    )
}
