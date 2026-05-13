#![no_std]

mod draw;
mod keyboard;
mod layout;
mod state;

use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::DrawTarget;

pub use state::{AppState, ColdWallet, WalletEvent};

pub fn draw_ui<D>(display: &mut D, wallet: &ColdWallet) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    draw::draw_ui(display, wallet.get_state(), wallet.mnemonic_words())
}
