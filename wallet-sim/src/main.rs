use std::path::{Path, PathBuf};

use embedded_graphics::geometry::Size;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics_simulator::{
    OutputSettingsBuilder, SimulatorDisplay, SimulatorEvent, Window,
    sdl2::MouseButton,
};
use wallet_core::{
    draw_ui, AppState, ColdWallet, PERSIST_BYTES, Secrets, WalletEvent,
    derive_key, encrypt_into_blob, layout::{SD_FILES_MAX, SD_FILE_H, SD_FILE_STEP, SD_FILE_W,
                                            SD_FILE_X, sd_file_y},
    MAX_PSBT_B64, NONCE_LEN, SALT_LEN,
};

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
        Descriptor             => "Descriptor",
        ShowMnemonic { page }  => match page {
            0 => "ShowMnemonic(1/4)", 1 => "ShowMnemonic(2/4)",
            2 => "ShowMnemonic(3/4)", _ => "ShowMnemonic(4/4)",
        },
        About                  => "About",
        PinMismatch            => "PinMismatch",
        PinLocked              => "PinLocked",
        PinVerifying { .. }    => "PinVerifying",
        PinConfirming { .. }   => "PinConfirming",
    }
}

// ── Simulated microSD ────────────────────────────────────────────────────────
//
// The exchange channel (roadmap v1 decision): a local folder plays the role
// of the card. The core only ever sees bytes and file *names* — it stays
// filesystem-blind. Convention: read `*.psbt`, write `<stem>-signed.psbt`.

fn sd_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".config").join("cold-wallet").join("sd")
}

/// Lists loadable PSBT files: `*.psbt`, excluding already-signed outputs,
/// sorted by name, capped at `SD_FILES_MAX`.
fn list_psbt_files(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".psbt") && !name.ends_with("-signed.psbt") {
                names.push(name);
            }
        }
    }
    names.sort();
    names.truncate(SD_FILES_MAX);
    names
}

/// "foo.psbt" → "foo-signed.psbt".
fn signed_name(name: &str) -> String {
    let stem = name.strip_suffix(".psbt").unwrap_or(name);
    format!("{stem}-signed.psbt")
}

/// Reads one PSBT file (Base64 text, as Sparrow exports) into the scan buffer.
fn read_psbt_file(path: &Path) -> Option<([u8; MAX_PSBT_B64], usize)> {
    let text = std::fs::read_to_string(path).ok()?;
    let text = text.trim();
    if text.is_empty() || text.len() > MAX_PSBT_B64 {
        eprintln!("[WALLET] Ignoring PSBT file (empty or too large): {}", path.display());
        return None;
    }
    let mut data = [0u8; MAX_PSBT_B64];
    data[..text.len()].copy_from_slice(text.as_bytes());
    Some((data, text.len()))
}

fn in_rect(x: i32, y: i32, rx: i32, ry: i32, rw: i32, rh: i32) -> bool {
    x >= rx && x < rx + rw && y >= ry && y < ry + rh
}

fn sd_row_at(x: i32, y: i32) -> Option<usize> {
    if !in_rect(x, y, SD_FILE_X, sd_file_y(0), SD_FILE_W, SD_FILE_STEP * SD_FILES_MAX as i32) {
        return None;
    }
    let row = ((y - sd_file_y(0)) / SD_FILE_STEP) as usize;
    let within_row = in_rect(x, y, SD_FILE_X, sd_file_y(row), SD_FILE_W, SD_FILE_H);
    (row < SD_FILES_MAX && within_row).then_some(row)
}

fn wallet_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".config").join("cold-wallet").join("wallet.bin")
}

/// Writes the image durably and atomically: write tmp → fsync tmp → rename →
/// fsync dir.
///
/// The `fsync`s matter for security, not just durability: the wallet write-ahead
/// increments the on-disk PIN-failure counter *before* checking the PIN, so that
/// power-cycling cannot rewind the lockout (no brute-force-by-restart). That
/// guarantee only holds if the increment has actually reached stable storage —
/// a buffered write lost to a power-cut would defeat it. We therefore fsync the
/// file before the rename and fsync the directory after, so both the new
/// contents and the rename are durable.
fn persist_blob(blob: &[u8; PERSIST_BYTES]) {
    use std::io::Write;

    let path = wallet_path();
    let Some(dir) = path.parent().map(std::path::Path::to_path_buf) else { return };
    let _ = std::fs::create_dir_all(&dir);
    let tmp = path.with_extension("bin.tmp");

    // Write + flush + fsync the temp file.
    let wrote = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(blob)?;
        f.flush()?;
        f.sync_all()?; // fsync file contents to stable storage
        Ok(())
    })();
    if wrote.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return;
    }

    if std::fs::rename(&tmp, &path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return;
    }

    // fsync the directory so the rename itself is durable.
    if let Ok(d) = std::fs::File::open(&dir) {
        let _ = d.sync_all();
    }
}

/// Loads the wallet from disk. Handles automatic migration from v1 (103 bytes,
/// unencrypted) to v3 (143 bytes, ChaCha20-Poly1305 + PBKDF2 + AAD-bound header).
///
/// The migration is *transparent*: the user notices nothing other than a one-time
/// extra delay at startup (PBKDF2 on the migrated PIN). A v2 blob (also 143 bytes
/// but empty AAD) is accepted by size here and then cleanly rejected by
/// `DiskHeader::parse` as a bad version — the user re-runs setup or restores.
fn load_wallet_image() -> Option<[u8; PERSIST_BYTES]> {
    let bytes = std::fs::read(wallet_path()).ok()?;
    match bytes.len() {
        PERSIST_BYTES => bytes.try_into().ok(),
        103 if bytes[102] == 1 => {
            println!("[WALLET] Legacy v1 wallet detected — migrating to v3 (encrypted)…");
            let v1: [u8; 103] = bytes.try_into().ok()?;
            let v3 = migrate_v1_to_v3(&v1)?;
            persist_blob(&v3);
            println!("[WALLET] Migration complete.");
            Some(v3)
        }
        n => {
            eprintln!("[WALLET] Ignoring wallet.bin with unknown size {n}");
            None
        }
    }
}

fn migrate_v1_to_v3(v1: &[u8; 103]) -> Option<[u8; PERSIST_BYTES]> {
    let mut ent  = [0u8; 32]; ent.copy_from_slice(&v1[0..32]);
    let mut seed = [0u8; 64]; seed.copy_from_slice(&v1[32..96]);
    let mut pin  = [0u8; 6];  pin.copy_from_slice(&v1[96..102]);

    let fresh = entropy();
    let mut salt  = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    salt.copy_from_slice(&fresh[..SALT_LEN]);
    nonce.copy_from_slice(&fresh[SALT_LEN..SALT_LEN + NONCE_LEN]);

    let key = derive_key(&pin, &salt);
    let secrets = Secrets { entropy: ent, seed };
    let blob = encrypt_into_blob(&secrets, &salt, &nonce, &key, 0, false).ok()?;
    // Zero locally-held PIN/key — secrets/seed/entropy are zeroed by Drop.
    for b in pin.iter_mut() { unsafe { core::ptr::write_volatile(b, 0); } }
    let mut k = key; for b in k.iter_mut() { unsafe { core::ptr::write_volatile(b, 0); } }
    Some(blob)
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sd = sd_dir();
    let _ = std::fs::create_dir_all(&sd);
    println!("[WALLET] SD folder: {}", sd.display());
    println!("[WALLET] Put Sparrow-exported *.psbt files there; signed output lands next to them.");

    let mut display = SimulatorDisplay::<Rgb565>::new(Size::new(SCREEN_WIDTH, SCREEN_HEIGHT));
    let mut wallet = match load_wallet_image() {
        Some(image) => match ColdWallet::from_disk_image(image, entropy()) {
            Some(w) => {
                println!("[WALLET] Persisted wallet found — resuming at PIN unlock");
                w
            }
            None => {
                eprintln!("[WALLET] Disk image rejected (bad header); starting fresh");
                ColdWallet::new()
            }
        },
        None => ColdWallet::new(),
    };

    let output_settings = OutputSettingsBuilder::new().scale(1).build();
    let mut window = Window::new("Cold Wallet — Simulator (testnet)", &output_settings);

    draw_ui(&mut display, &wallet, &[])?;

    // Side-effects owned by the sim (the core stays filesystem-blind):
    let mut loaded_file: Option<String> = None;   // PSBT currently under review
    let mut signed_written = false;               // signed output written for this load
    let mut descriptor_written = false;           // descriptor.txt exported this session
    let mut sd_list: Vec<String> = Vec::new();    // current SignScan file listing

    'running: loop {
        window.update(&display);

        // Collect into an owned Vec so the immutable borrow of `window` is
        // released before the loop body, allowing `window.update()` inside.
        #[allow(clippy::needless_collect)]
        let events: Vec<_> = window.events().collect();
        // Set when a click redraws the screen: the other clicks of this batch
        // were aimed at the screen we just left. The drain at the end of the
        // arm covers the ones still in SDL's queue.
        let mut swallowed = false;
        for event in events {
            match event {
                SimulatorEvent::Quit => break 'running,
                SimulatorEvent::MouseButtonUp { mouse_btn: MouseButton::Left, point } => {
                    if swallowed { continue; }
                    let before = wallet.get_state();
                    // Whether this click changed what is on screen.
                    let mut screen_redrawn = false;

                    // Persist closure: receives the wallet's current on-disk image
                    // every time the wallet needs to be written (write-ahead before
                    // a PIN check, after successful unlock, after PIN setup / change).
                    let mut persist = |blob: &[u8; PERSIST_BYTES]| {
                        persist_blob(blob);
                    };

                    // In SignScan, a tap on a file row loads that PSBT file.
                    if matches!(before, AppState::SignScan) {
                        if let Some(row) = sd_row_at(point.x, point.y) {
                            if let Some(name) = sd_list.get(row) {
                                println!("[WALLET] Loading {name}…");
                                if let Some((data, len)) = read_psbt_file(&sd.join(name)) {
                                    loaded_file = Some(name.clone());
                                    signed_written = false;
                                    wallet.handle_event(WalletEvent::PsbtScanned { data, len }, &mut persist);
                                }
                            }
                        } else {
                            wallet.handle_event(
                                WalletEvent::Touch { x: point.x, y: point.y, entropy: entropy() },
                                &mut persist,
                            );
                        }
                    } else {
                        wallet.handle_event(
                            WalletEvent::Touch { x: point.x, y: point.y, entropy: entropy() },
                            &mut persist,
                        );
                    }

                    let after = wallet.get_state();

                    // Entering SignScan: refresh the file listing shown on screen.
                    if matches!(after, AppState::SignScan) && !matches!(before, AppState::SignScan) {
                        sd_list = list_psbt_files(&sd);
                        if sd_list.is_empty() {
                            println!("[WALLET] No *.psbt file in {} — export one from Sparrow", sd.display());
                        }
                        loaded_file = None;
                        signed_written = false;
                    }

                    if before != after {
                        log_transition(before, after);
                    }

                    // Reaching Home: export the descriptor once per session so the
                    // hot side can import the wallet.
                    if matches!(after, AppState::Home)
                        && !descriptor_written
                        && let Some(desc) = wallet.descriptor()
                    {
                        let path = sd.join("descriptor.txt");
                        match std::fs::write(&path, desc) {
                            Ok(()) => {
                                descriptor_written = true;
                                println!("[WALLET] Descriptor exported to {}", path.display());
                            }
                            Err(e) => eprintln!("[WALLET] Descriptor write failed: {e}"),
                        }
                    }

                    // Signature completed for the loaded file: write the signed PSBT
                    // next to it, in the same Base64 form Sparrow imports.
                    if matches!(after, AppState::SignResult)
                        && !signed_written
                        && let Some(name) = &loaded_file
                        && let Some(signed) = wallet.signed_psbt_b64()
                    {
                        let path = sd.join(signed_name(name));
                        match std::fs::write(&path, signed) {
                            Ok(()) => {
                                signed_written = true;
                                println!("[WALLET] Signed PSBT written to {}", path.display());
                            }
                            Err(e) => eprintln!("[WALLET] Signed write failed: {e}"),
                        }
                    }

                    if before != after {
                        draw_ui(&mut display, &wallet, &sd_list.iter().map(|s| s.as_str()).collect::<Vec<_>>())?;
                        screen_redrawn = true;
                    }

                    // Two-phase resolution: if the input parked us in a
                    // verifying/confirming state, we just drew the spinner;
                    // now perform the heavy PBKDF2 + AEAD pass and redraw.
                    if wallet.has_pending_work() {
                        // Push the spinner frame to the screen *before* blocking
                        // on the KDF — without this, SDL may batch the draw
                        // with the post-KDF redraw and the user sees nothing.
                        window.update(&display);
                        let mid = wallet.get_state();
                        wallet.process_pending(entropy(), &mut persist);
                        let resolved = wallet.get_state();
                        if mid != resolved {
                            log_transition(mid, resolved);
                            if matches!(mid, AppState::PinConfirming { .. })
                                && matches!(resolved, AppState::Home)
                            {
                                println!("[WALLET] Wallet saved (encrypted) to {}", wallet_path().display());
                            }
                            draw_ui(&mut display, &wallet, &sd_list.iter().map(|s| s.as_str()).collect::<Vec<_>>())?;
                            screen_redrawn = true;
                        }
                    }

                    // Redraw when entering SignScan (file listing appeared).
                    if matches!(after, AppState::SignScan) && !matches!(before, AppState::SignScan) {
                        draw_ui(&mut display, &wallet, &sd_list.iter().map(|s| s.as_str()).collect::<Vec<_>>())?;
                        screen_redrawn = true;
                    }

                    // A click just swapped the screen, so every other click was
                    // aimed at the one we left. The PIN pad sits on top of the
                    // Home grid: the tap that validates the 6th digit falls on
                    // the SignScan button (keys 3-4), Receive (keys 0-1) or
                    // Settings (keys 8-9). A user who clicks twice, impatient
                    // during the ~1.5 s PBKDF2 pass, would otherwise land on
                    // SignScan right after unlocking. Drop what SDL still holds
                    // and ignore the rest of this batch.
                    if screen_redrawn {
                        for ev in window.events() {
                            if matches!(ev, SimulatorEvent::Quit) { break 'running; }
                        }
                        swallowed = true;
                    }
                }
                _ => {}
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(16));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_psbt_files_sorted_and_filters_signed() {
        let dir = std::env::temp_dir().join(format!("cw-sd-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("b.psbt"), "AAAA").unwrap();
        std::fs::write(dir.join("a.psbt"), "BBBB").unwrap();
        std::fs::write(dir.join("a-signed.psbt"), "CCCC").unwrap();
        std::fs::write(dir.join("note.txt"), "").unwrap();

        let files = list_psbt_files(&dir);
        assert_eq!(files, vec!["a.psbt".to_string(), "b.psbt".to_string()]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn signed_name_appends_suffix() {
        assert_eq!(signed_name("foo.psbt"), "foo-signed.psbt");
        assert_eq!(signed_name("noext"), "noext-signed.psbt");
    }

    #[test]
    fn sd_row_hit_test_matches_layout() {
        // Row 0 and row 1 are hittable, outside rows are not.
        assert_eq!(sd_row_at(SD_FILE_X + 5, sd_file_y(0) + 30), Some(0));
        assert_eq!(sd_row_at(SD_FILE_X + 5, sd_file_y(0) + SD_FILE_STEP + 30), Some(1));
        assert_eq!(sd_row_at(SD_FILE_X + 5, sd_file_y(0) + 4 * SD_FILE_STEP + 30), None, "beyond max rows");
        assert_eq!(sd_row_at(SD_FILE_X - 1, sd_file_y(0) + 30), None, "outside horizontally");
    }
}
