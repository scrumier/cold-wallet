#![cfg_attr(not(feature = "std"), no_std)]

mod base64;
mod crypto;
mod derive;
mod draw;
mod keyboard;
pub mod layout;
mod psbt;
mod sighash;
mod signing;
mod state;
pub mod storage;

use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::DrawTarget;

pub use derive::{CHANGE_BRANCH, KEY_WINDOW, NETWORK, OWN_KEY_COUNT, RECEIVE_BRANCH};
pub use psbt::{b64_len, MAX_PSBT_B64, MAX_PSBT_RAW, MAX_SIGNED_B64, MAX_SIGNED_RAW};
pub use state::{AppState, ColdWallet, WalletEvent};
pub use storage::{DiskHeader, DiskError, Secrets, PERSIST_BYTES, VERSION_V3,
                  encrypt_into_blob, try_decrypt};
pub use crypto::{derive_key, KEY_LEN, NONCE_LEN, SALT_LEN};

/// Draws the current wallet state. `sd_files` is the list of `*.psbt` file
/// names offered by the platform layer (the simulated SD folder today, the
/// real card at portage time) — the core never touches the filesystem, it
/// only renders what it is given.
pub fn draw_ui<D>(
    display: &mut D,
    wallet: &ColdWallet,
    sd_files: &[&str],
) -> Result<(), D::Error>
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
        wallet.descriptor(),
        wallet.own_output_keys().map(|keys| &keys[..]),
        sd_files,
        wallet.scan_error(),
    )
}
