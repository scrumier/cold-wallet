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

fn entropy() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0xDEAD_BEEF)
}

fn log_transition(before: AppState, after: AppState) {
    use AppState::*;
    match (before, after) {
        (EnterPassphrase { .. }, EnterPassphrase { buf, len }) => {
            let typed = core::str::from_utf8(&buf[..len as usize]).unwrap_or("?");
            println!("[WALLET] passphrase: \"{typed}\"");
        }
        (SetPin { len: before_len, .. }, SetPin { len: after_len, .. }) => {
            println!("[WALLET] SetPin: {after_len}/6 digits entered (was {before_len})");
        }
        (ConfirmPin { len: before_len, .. }, ConfirmPin { len: after_len, .. }) => {
            println!("[WALLET] ConfirmPin: {after_len}/6 digits entered (was {before_len})");
        }
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
        EnterPin               => "EnterPin",
        Home                   => "Home",
        Receive                => "Receive",
        SignScan               => "SignScan",
        SignReview             => "SignReview",
        SignResult             => "SignResult",
        Accounts               => "Accounts",
        Settings               => "Settings",
        ShowMnemonic           => "ShowMnemonic",
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

    draw_ui(&mut display, wallet.get_state())?;

    'running: loop {
        window.update(&display);

        for event in window.events() {
            match event {
                SimulatorEvent::Quit => break 'running,
                SimulatorEvent::MouseButtonUp { mouse_btn: MouseButton::Left, point } => {
                    let before = wallet.get_state();
                    wallet.handle_event(WalletEvent::Touch { x: point.x, y: point.y, entropy: entropy() });
                    let after = wallet.get_state();
                    if before != after {
                        log_transition(before, after);
                        draw_ui(&mut display, after)?;
                    }
                }
                _ => {}
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(16));
    }

    Ok(())
}
