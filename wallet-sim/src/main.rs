use embedded_graphics::geometry::Size;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics_simulator::{
    OutputSettingsBuilder, SimulatorDisplay, SimulatorEvent, Window,
    sdl2::MouseButton,
};
use wallet_core::{draw_ui, AppState, ColdWallet, WalletEvent};

// Viewfinder hit area — matches layout::SIGN_VF_* constants.
const VF_X: i32 = 200; // (800 - 400) / 2
const VF_Y: i32 = 70;
const VF_W: i32 = 400;
const VF_H: i32 = 300;

const SCREEN_WIDTH: u32  = 800;
const SCREEN_HEIGHT: u32 = 480;

fn entropy() -> [u8; 32] {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("entropy source unavailable");
    buf
}

fn log_transition(before: AppState, after: AppState) {
    use AppState::*;
    match (before, after) {
        // Restore: word confirmed — log count only, never the word itself
        (RestoreWallet { word_idx: wi_before, .. },
         RestoreWallet { word_idx: wi_after, error: false, .. })
            if wi_after > wi_before =>
        {
            println!("[WALLET] Restore: {wi_after}/24 words confirmed");
        }
        // Restore: bad checksum
        (RestoreWallet { .. }, RestoreWallet { error: true, .. }) =>
            println!("[WALLET] Restore: invalid mnemonic checksum — please re-enter all 24 words"),
        // Restore complete → passphrase entry
        (RestoreWallet { .. }, EnterPassphrase { .. }) =>
            println!("[WALLET] Restore: all 24 words accepted"),
        // Restore: regular typing / no meaningful change — stay silent
        (RestoreWallet { .. }, RestoreWallet { .. }) => {}

        (EnterPassphrase { .. }, EnterPassphrase { len, .. }) =>
            println!("[WALLET] passphrase: {len} char(s) typed"),
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
        RestoreWallet { word_idx, .. } => {
            if word_idx < 24 { "RestoreWallet(entry)" } else { "RestoreWallet(done)" }
        }
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
        PinLocked              => "PinLocked",
    }
}

/// Builds a minimal single-input P2TR test PSBT for the given x-only internal key,
/// returns it Base64-encoded. The "transaction" sends 100k sats to the same address.
fn make_test_psbt_b64(internal_key: [u8; 32]) -> ([u8; 512], usize) {
    // Compute tweaked output key (P2TR scriptPubKey witness program).
    // We replicate the taproot tweak here using raw bytes.
    use bitcoin_hashes::{sha256, HashEngine};

    let tag = sha256::Hash::hash(b"TapTweak");
    let mut eng = sha256::Hash::engine();
    eng.input(tag.as_ref());
    eng.input(tag.as_ref());
    eng.input(&internal_key);
    let tweak_hash = sha256::Hash::from_engine(eng);
    let tweak_bytes: [u8; 32] = {
        let mut b = [0u8; 32];
        b.copy_from_slice(tweak_hash.as_ref());
        b
    };

    use k256::{ProjectivePoint, AffinePoint, Scalar};
    use k256::elliptic_curve::{PrimeField, sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint}};

    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(&internal_key);
    let enc = EncodedPoint::<k256::Secp256k1>::from_bytes(compressed).unwrap();
    let p = AffinePoint::from_encoded_point(&enc).unwrap();
    let t: Scalar = Scalar::from_repr(tweak_bytes.into()).unwrap();
    let q = ProjectivePoint::from(p) + ProjectivePoint::GENERATOR * t;
    let q_enc = AffinePoint::from(q).to_encoded_point(true);
    let mut output_key = [0u8; 32];
    output_key.copy_from_slice(&q_enc.as_bytes()[1..]);

    let mut spk = [0u8; 34];
    spk[0] = 0x51; // OP_1
    spk[1] = 0x20; // OP_PUSHBYTES_32
    spk[2..].copy_from_slice(&output_key);

    // Serialise a minimal PSBT v0 by hand.
    // Global map: magic + separator + PSBT_GLOBAL_UNSIGNED_TX (key=0x00)
    // One input: PSBT_IN_WITNESS_UTXO (0x01) + PSBT_IN_TAP_INTERNAL_KEY (0x12)
    // One output: empty map
    let mut buf = [0u8; 1024];
    let mut pos = 0usize;

    let w = |buf: &mut [u8; 1024], p: &mut usize, b: u8| { buf[*p] = b; *p += 1; };
    let wslice = |buf: &mut [u8; 1024], p: &mut usize, s: &[u8]| {
        buf[*p..*p + s.len()].copy_from_slice(s); *p += s.len();
    };
    let varint = |buf: &mut [u8; 1024], p: &mut usize, n: usize| {
        if n < 0xfd { w(buf, p, n as u8); }
        else { w(buf, p, 0xfd); w(buf, p, (n & 0xff) as u8); w(buf, p, ((n >> 8) & 0xff) as u8); }
    };

    // PSBT magic
    wslice(&mut buf, &mut pos, b"psbt\xff");

    // Global unsigned tx (key=0x00)
    // Build the raw unsigned tx first.
    let mut tx = [0u8; 200];
    let mut tp = 0usize;
    let tw = |tb: &mut [u8; 200], tp: &mut usize, b: u8| { tb[*tp] = b; *tp += 1; };
    let twslice = |tb: &mut [u8; 200], tp: &mut usize, s: &[u8]| {
        tb[*tp..*tp + s.len()].copy_from_slice(s); *tp += s.len();
    };
    // version (le u32 = 2)
    twslice(&mut tx, &mut tp, &[2u8, 0, 0, 0]);
    // input count varint = 1
    tw(&mut tx, &mut tp, 1);
    // input: txid (32 bytes, all 0xab), vout (le u32 = 0), script_len = 0, sequence
    twslice(&mut tx, &mut tp, &[0xabu8; 32]);
    twslice(&mut tx, &mut tp, &[0u8; 4]); // vout = 0
    tw(&mut tx, &mut tp, 0);              // scriptSig len = 0
    twslice(&mut tx, &mut tp, &[0xff, 0xff, 0xff, 0xff]); // sequence
    // output count = 1
    tw(&mut tx, &mut tp, 1);
    // output: amount (le u64 = 99_000 sats), scriptPubKey
    twslice(&mut tx, &mut tp, &99_000u64.to_le_bytes());
    tw(&mut tx, &mut tp, 34); // scriptPubKey len
    twslice(&mut tx, &mut tp, &spk);
    // locktime (le u32 = 0)
    twslice(&mut tx, &mut tp, &[0u8; 4]);

    let tx_len = tp;
    varint(&mut buf, &mut pos, 1);  // key len = 1
    w(&mut buf, &mut pos, 0x00);    // key = PSBT_GLOBAL_UNSIGNED_TX
    varint(&mut buf, &mut pos, tx_len);
    wslice(&mut buf, &mut pos, &tx[..tx_len]);
    // separator (end of global map)
    w(&mut buf, &mut pos, 0x00);

    // Input 0 map: PSBT_IN_WITNESS_UTXO (key=0x01)
    varint(&mut buf, &mut pos, 1);  // key len = 1
    w(&mut buf, &mut pos, 0x01);    // key
    // value = witness utxo: amount (8 bytes le) + scriptPubKey (varint + bytes)
    let utxo_val_len = 8 + 1 + 34;
    varint(&mut buf, &mut pos, utxo_val_len);
    wslice(&mut buf, &mut pos, &100_000u64.to_le_bytes()); // 100k sats
    w(&mut buf, &mut pos, 34);      // scriptPubKey len
    wslice(&mut buf, &mut pos, &spk);

    // PSBT_IN_TAP_INTERNAL_KEY (key=0x12)
    varint(&mut buf, &mut pos, 1);  // key len = 1
    w(&mut buf, &mut pos, 0x12);    // key
    varint(&mut buf, &mut pos, 32); // value len = 32
    wslice(&mut buf, &mut pos, &internal_key);
    // end of input 0
    w(&mut buf, &mut pos, 0x00);

    // Output 0 map: empty
    w(&mut buf, &mut pos, 0x00);

    let psbt_len = pos;

    // Base64-encode.
    let b64_cap = psbt_len.div_ceil(3) * 4;
    let mut b64 = [0u8; 512];
    let b64_len = base64_encode(&buf[..psbt_len], &mut b64[..b64_cap.min(512)]);
    (b64, b64_len)
}

/// Minimal base64 encoder (duplicates wallet_core's private impl so we don't expose it).
fn base64_encode(input: &[u8], out: &mut [u8]) -> usize {
    const ENC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut i = 0;
    let mut o = 0;
    while i + 2 < input.len() {
        let (a, b, c) = (input[i] as usize, input[i+1] as usize, input[i+2] as usize);
        out[o]     = ENC[a >> 2];
        out[o + 1] = ENC[((a << 4) | (b >> 4)) & 0x3f];
        out[o + 2] = ENC[((b << 2) | (c >> 6)) & 0x3f];
        out[o + 3] = ENC[c & 0x3f];
        i += 3; o += 4;
    }
    match input.len() - i {
        1 => { let a = input[i] as usize;
               out[o] = ENC[a >> 2]; out[o+1] = ENC[(a << 4) & 0x3f];
               out[o+2] = b'='; out[o+3] = b'='; o += 4; }
        2 => { let (a, b) = (input[i] as usize, input[i+1] as usize);
               out[o] = ENC[a >> 2]; out[o+1] = ENC[((a << 4) | (b >> 4)) & 0x3f];
               out[o+2] = ENC[(b << 2) & 0x3f]; out[o+3] = b'='; o += 4; }
        _ => {}
    }
    o
}

fn in_rect(x: i32, y: i32, rx: i32, ry: i32, rw: i32, rh: i32) -> bool {
    x >= rx && x < rx + rw && y >= ry && y < ry + rh
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

                    // In SignScan, a tap in the viewfinder simulates a QR scan.
                    if matches!(before, AppState::SignScan)
                        && in_rect(point.x, point.y, VF_X, VF_Y, VF_W, VF_H)
                    {
                        if let Some(ik) = wallet.tap_internal_key() {
                            println!("[WALLET] SignScan: injecting test PSBT…");
                            let (data, len) = make_test_psbt_b64(ik);
                            wallet.handle_event(WalletEvent::PsbtScanned { data, len });
                        } else {
                            println!("[WALLET] SignScan: no key derived yet — complete wallet setup first");
                        }
                    } else {
                        wallet.handle_event(WalletEvent::Touch {
                            x: point.x, y: point.y, entropy: entropy(),
                        });
                    }

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
