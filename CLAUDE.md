# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
cargo build --workspace       # build all crates
cargo test --workspace        # run all tests
cargo clippy --workspace -- -D warnings  # lint (CI enforces zero warnings)
cargo run -p wallet-sim       # run the desktop simulator
```

## Project goal

Air-gapped **Bitcoin** cold wallet targeting **bare-metal STM32H747** (dual-core Cortex-M7+M4). The private key never touches a connected device. The only I/O channel is QR codes.

**Hardware cible :**
- Board : STM32H747I-DISCO
- Écran : LCD-TFT via contrôleur LTDC intégré
- Caméra : OV5640 via interface DCMI (I2C pour config, DCMI pour les données)
- Runtime async : Embassy (`embassy-stm32`)
- HAL : `stm32h7xx-hal`
- Stratégie cœurs : M7 → crypto + logique wallet / M4 → UI + périphériques

## Signing flow (PSBT)

```
Online device                    Cold wallet (this project)
─────────────────────────────────────────────────────────────
Build unsigned tx → PSBT ──QR──▶ Scan & parse PSBT (BIP174)
                                  Display tx details to user
                                  Sign with xprv (secp256k1)
Broadcast to network ◀──QR────── Display signed PSBT
```

## UX & input

- **Input** : écran tactile capacitif (coordonnées X/Y). Sur le simulateur Mac → clics souris. Sur STM32H747I-DISCO → contrôleur tactile intégré. Même interface, zéro différence de code dans `wallet-core`.
- **PIN** : pavé numérique virtuel avec chiffres mélangés aléatoirement à chaque affichage (anti-analyse de traces de doigts)
- **Passphrase & texte** : clavier QWERTY virtuel sur l'écran
- **Restauration mnémonique** : clavier virtuel avec autocomplétion sur les 2048 mots BIP39
- **Navigation** : boutons tactiles (Confirmer / Annuler / Retour) affichés à l'écran

## Écrans & flux

```
Premier démarrage
  Splash → Nouveau wallet | Restaurer wallet
    Nouveau  : afficher 24 mots → passphrase (opt.) → PIN → confirmer PIN → Home
    Restaurer: saisir 24 mots  → passphrase (opt.) → PIN → confirmer PIN → Home

Déverrouillage
  Splash → Saisir PIN → Home

Home
  ├─ Recevoir    → adresse bc1p + QR
  ├─ Signer      → scanner QR → vérifier tx → confirmer → QR signé
  ├─ Comptes     → liste / ajouter
  └─ Paramètres  → afficher mnémonique (PIN requis) | changer PIN | à propos
```

## Feature scope

- **Adresses** : Taproot uniquement (BIP86, `bc1p`) — pas de SegWit ni Legacy
- **Mnémonique** : 24 mots (BIP39)
- **Passphrase** : BIP39 passphrase supportée (25ème mot optionnel)
- **Comptes** : multi-compte (plusieurs wallets dérivés sur le même device)

## Key standards

| BIP | Role |
|-----|------|
| BIP39 | Mnémonique 24 mots + passphrase optionnelle → seed 512 bits |
| BIP32 | HD derivation: seed → master xprv → child keys (HMAC-SHA512) |
| BIP86 | Taproot path: `m/86'/0'/0'/0/n` (P2TR) |
| BIP174 | PSBT — unsigned tx container exchanged via QR |

Derivation chain: mnemonic + passphrase → BIP39 seed → BIP32 xprv → BIP86 path → leaf key → Schnorr sign (k256).

## Crate choices (workspace dependencies — all `no_std`)

| Crate | Version | Purpose |
|-------|---------|---------|
| `k256` | 0.13.4 | secp256k1 ECDSA + BIP340 Schnorr signing |
| `bip32` | 0.5.3 | HD key derivation |
| `bip39` | 2.2.2 | Mnemonic generation & seed derivation |
| `bitcoin_hashes` | 0.20.0 | SHA256, SHA256d, RIPEMD160 |
| `qrcode` | 0.14.1 | QR code generation (`default-features = false`) |

All used with `default-features = false`. `wallet-core` must stay `#![no_std]` — no `std`, no `alloc` without a feature flag.

## Rust idioms (edition 2024)

- **Let chains** — utiliser `if let Some(a) = x && let Some(b) = y` plutôt que des `if let` imbriqués
- **Erreurs `no_std`** — enums d'erreur concrètes avec `impl fmt::Display` + `From` pour le `?`. Pas d'`anyhow`/`thiserror`
- **Pas d'alloc par défaut** — préférer les tableaux stack avec const generics, les types par référence
- **Panic** — `panic-halt` en dev, `panic-abort` en release (importés via `use panic_xxx as _`)
- **Clippy** — `deny(clippy::correctness)`, `warn(clippy::perf)`, `warn(clippy::pedantic)` sélectivement
- **Const fn** — stable pour types primitifs, utile pour tables/constantes calculées à compile-time

## Architecture

Three crates in the workspace:

- **`wallet-core`** — `#![no_std]` library. Contains `ColdWallet` state machine, `AppState` enum, all Bitcoin logic, and `draw_ui` / screen functions generic over `DrawTarget<Color=Rgb565>`. Zero hardware knowledge — reçoit des frames caméra (`&[u8]`) et dessine sur n'importe quel `DrawTarget`.
- **`wallet-sim`** — Desktop simulator (`std`, macOS). Branche la webcam Mac (`nokhwa` + AVFoundation) et une fenêtre `embedded-graphics-simulator` **800×480 px RGB565** (dimensions exactes du STM32H747I-DISCO). Scale ×2 pour HiDPI.
- **`wallet-h747`** *(à créer quand le hardware arrive)* — Crate Embassy bare-metal. Branche le pilote DCMI OV5640 et le contrôleur LTDC à la place de la webcam/fenêtre Mac. Le portage = remplacer ce seul crate.

**Règle de portage :** tout ce qui est hardware-dépendant (caméra, écran, timer, RNG) vit dans `wallet-sim` ou `wallet-h747`. `wallet-core` ne contient aucune dépendance plateforme.

**Display cible :** 800×480 px, RGB565, 4" LCD MIPI DSI (STM32H747I-DISCO).

When adding UI states: add a variant to `AppState` in `wallet-core/src/lib.rs` and a match arm in `draw_ui`. Keep all crypto and wallet logic inside `wallet-core`.
