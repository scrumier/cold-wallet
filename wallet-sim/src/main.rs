use embedded_graphics::geometry::Size;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics_simulator::{
    OutputSettingsBuilder, SimulatorDisplay, SimulatorEvent, Window,
    sdl2::MouseButton,
};
use std::time::{SystemTime, UNIX_EPOCH};
use wallet_core::{draw_ui, AppState, ColdWallet, WalletEvent};

const SCREEN_WIDTH: u32  = 800;
const SCREEN_HEIGHT: u32 = 480;

fn entropy() -> [u8; 32] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0xDEAD_BEEF_DEAD_BEEF);
    let mut buf = [0u8; 32];
    let mut s = nanos;
    for chunk in buf.chunks_mut(8) {
        s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        let bytes = s.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    buf
}

fn log_transition(before: AppState, after: AppState) {
    use AppState::*;
    match (before, after) {
        (EnterPassphrase { .. }, EnterPassphrase { buf, len }) => {
            let typed = core::str::from_utf8(&buf[..len as usize]).unwrap_or("?");
            println!("[WALLET] passphrase: \"{typed}\"");
        }
        (SetPin { len: bl, .. }, SetPin { len: al, .. }) =>
            println!("[WALLET] SetPin: {al}/6 digits (was {bl})"),
        (ConfirmPin { len: bl, .. }, ConfirmPin { len: al, .. }) =>
            println!("[WALLET] ConfirmPin: {al}/6 digits (was {bl})"),
        (EnterPin { len: bl, .. }, EnterPin { len: al, .. }) =>
            println!("[WALLET] EnterPin: {al}/6 digits (was {bl})"),
        _ => println!("[WALLET] {} → {}", state_name(before), state_name(after)),
    }
}

fn state_name(state: AppState) -> &'static str {
    use AppState::*;
    match state {
        Welcome                => "Welcome",
        NewWallet { page }     => match page {
            0 => "NewWallet(1/4)", 1 => "NewWallet(2/4)",
            2 => "NewWallet(3/4)", _ => "NewWallet(4/4)",
        },
        RestoreWallet          => "RestoreWallet",
        EnterPassphrase { .. } => "EnterPassphrase",
        SetPin { .. }          => "SetPin",
        ConfirmPin { .. }      => "ConfirmPin",
        EnterPin { .. }        => "EnterPin",
        Home                   => "Home",
        Receive                => "Receive",
        SignScan               => "SignScan",
        SignReview             => "SignReview",
        SignResult             => "SignResult",
        Accounts               => "Accounts",
        Settings               => "Settings",
        ShowMnemonic { page }  => match page {
            0 => "ShowMnemonic(1/4)", 1 => "ShowMnemonic(2/4)",
            2 => "ShowMnemonic(3/4)", _ => "ShowMnemonic(4/4)",
        },
        ChangePin              => "ChangePin",
        About                  => "About",
        PinMismatch            => "PinMismatch",
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut display = SimulatorDisplay::<Rgb565>::new(Size::new(SCREEN_WIDTH, SCREEN_HEIGHT));
    let mut wallet  = ColdWallet::new();

    let output_settings = OutputSettingsBuilder::new().scale(1).build();
    let mut window = Window::new("Cold Wallet — Simulator", &output_settings);

    draw_ui(&mut display, &wallet)?;

    'running: loop {
        window.update(&display);

        for event in window.events() {
            match event {
                SimulatorEvent::Quit => break 'running,
                SimulatorEvent::MouseButtonUp { mouse_btn: MouseButton::Left, point } => {
                    let before = wallet.get_state();
                    wallet.handle_event(WalletEvent::Touch {
                        x: point.x, y: point.y, entropy: entropy(),
                    });
                    let after = wallet.get_state();
                    if before != after {
                        log_transition(before, after);
                        draw_ui(&mut display, &wallet)?;
                    }
                }
                _ => {}
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(16));
    }

    Ok(())
}
