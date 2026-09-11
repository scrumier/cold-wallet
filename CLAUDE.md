# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
cargo build --workspace       # build all crates
cargo test --workspace        # run all tests
cargo clippy --workspace -- -D warnings  # lint (CI enforces zero warnings)
cargo run -p wallet-sim       # run the desktop simulator (needs SDL2)
cargo build -p wallet-core --target thumbv7em-none-eabihf  # bare-metal cross-check
```

## Project goal

Air-gapped **Bitcoin** cold wallet. Firmware cible : une carte custom à base de **STM32H753** (voir `ROADMAP.md` — développée d'abord sur le simulateur, puis sur dev board, puis sur notre PCB). The private key never touches a connected device.

**Canal d'échange v1 (décidé le 14/08/2026) : microSD.** Lire `*.psbt`, écrire `*-signed.psbt`. Implémenté dans le simulateur via un répertoire local (`~/.config/cold-wallet/sd/`) : la liste des fichiers est affichée sur SignScan, le signé est écrit à côté. La caméra et le décodage QR restent hors périmètre v1 ; la **génération** de QR (adresse, descriptor) existe. Voir `ROADMAP.md`.

**Hardware cible (décidé le 11/09/2026) : carte dessinée par nous**, pas de carte de démo :
- **MCU : STM32H753VIT6 en LQFP100** — soudable à la main, et **SHA-256 matériel** (le PBKDF2 du PIN tombe de ~10 s à ~0,2 s sur cible)
- **Écran : SPI 320×240 RGB565** (ILI9341/ST7735, drivers Rust existants) — framebuffer en RAM interne, **pas de SDRAM**
- **microSD en SPI** (le même canal que le simulateur)
- **PCB 4 couches** (JLCPCB) ; assemblage MCU/passifs par JLC, connecteurs à la main
- Banc d'essai en attendant la carte : **WeAct STM32H743 core board** (~20 €, déjà soudé)
- Tactile : résistif (XPT2046) ou boutons physiques mappés sur des zones — à décider au design

**Règles de portage, non négociables (décidées le 14/08/2026) :**
1. **Tout tourne sur le M7.** Un seul cœur, rien qui suppose du multi-cœur.
2. **Aucun secret hors DTCM.** Seed, PIN, clés dérivées vivent en DTCM (accès CPU direct, pas de DMA). L'écran SPI et la SD n'y touchent jamais — la frontière est explicite dans le schéma.

## Signing flow (v1 : microSD)

```
Online device (Sparrow)          Cold wallet (this project)
─────────────────────────────────────────────────────────────
Import descriptor.txt ────────── Export descriptor (Settings + SD)
Build unsigned PSBT              Read *.psbt from SD folder
Export *.psbt to SD folder ────▶ Display tx details to user
                                 Sign (BIP341 key-path, BIP340 Schnorr)
Import *-signed.psbt, broadcast ◀ Write *-signed.psbt to SD folder
```

**État réel de la boucle, à ne pas surestimer :**
- Le simulateur lit et écrit de vrais fichiers PSBT dans le dossier SD — plus d'injection synthétique. La boucle avec Sparrow (import descriptor → PSBT → signature → diffusion) est prête à être essayée : c'est le jalon de `ROADMAP.md` phase 3.
- Les champs PSBT inconnus (derivations BIP32, clés inconnues) sont toujours **jetés** à la ré-émission : la tx non signée, elle, est préservée octet pour octet. Si Sparrow refuse un PSBT signé, c'est le premier suspect.

## État sécurité (réel, aujourd'hui)

- Mnémonique 24 mots + passphrase → seed ; PIN 6 chiffres ; blob v3 chiffré ChaCha20-Poly1305, clé = PBKDF2-HMAC-SHA256 (1M itérations, écrit à la main, testé contre RFC 4231/7914), version+salt liés en AAD.
- Compteur d'échecs PIN écrit **avant** vérification (write-ahead + fsync), comparaison constant-time, secrets effacés en `write_volatile` + `Drop`.
- **Décidé mais pas encore implémenté** (roadmap phase 2) : ne stocker que l'entropie, redemander la passphrase au déverrouillage, wipe après N échecs. Aujourd'hui le seed complet (passphrase incorporée) est stocké et la passphrase n'est jamais redemandée.
- Défauts connus et non corrigés : **F-05** (aucune vérification de mnémonique à la création) et **F-06** (montants d'input fournis par l'hôte, à documenter) dans `REVIEW-2026-08-14.md`. F-01 à F-04 sont corrigés (fenêtre de dérivation, sighash type, PSBT préservé, limites alignées).

## UX & input

- **Input** : écran tactile capacitif (X/Y). Sur le simulateur → clics souris. Sur la carte → contrôleur tactile FT5336. Même interface, zéro différence de code dans `wallet-core`.
- **PIN** : pavé numérique virtuel, chiffres mélangés à chaque affichage (splitmix64 sur entropie plateforme)
- **Passphrase & texte** : clavier virtuel à l'écran
- **Restauration** : clavier virtuel avec autocomplétion sur les 2048 mots BIP39
- **Navigation** : boutons tactiles (Confirmer / Annuler / Retour)

## Feature scope

- **Adresses** : Taproot uniquement (BIP86) — pas de SegWit ni Legacy
- **Réseau : testnet4** (`NETWORK` dans `derive.rs` : HRP `tb`, coin type `1'`). Testnet3 est déprécié. Le mainnet est un changement de constante, volontairement pas un paramètre runtime — un firmware ne peut pas dériver les deux réseaux par accident.
- **Mnémonique** : 24 mots (BIP39), passphrase optionnelle
- **Dérivation : fenêtre fixe** `m/86'/1'/0'/{receive 0 | change 1}/{0..19}`. Le multi-compte est hors périmètre (assumé, voir `ROADMAP.md`) et le bouton « Comptes » reste un écran mort.
- **Descriptor** : `tr([<fingerprint>/86h/1h/0h]<tpub>/<0;1>/*)` avec checksum BIP380, affiché en Settings et écrit dans le dossier SD.

## Key standards

| BIP | Role |
|-----|------|
| BIP39 | Mnémonique 24 mots + passphrase optionnelle → seed 512 bits |
| BIP32 | HD derivation: seed → master xprv → child keys (HMAC-SHA512) |
| BIP86 | Compte `m/86'/{coin}'/0'`, fenêtre receive/change 0..19 |
| BIP174 | PSBT container (tx non signée préservée octet pour octet) |
| BIP340/341 | Schnorr + Taproot key-path sighash (SIGHASH_DEFAULT uniquement) |
| BIP350 | bech32m (`tb1p`/`bc1p`), encodeur écrit ici, vecteurs officiels testés |
| BIP380/386 | Descriptor `tr(...)` + checksum, écrits ici |

## Crates (workspace, tous `no_std`)

| Crate | Version | Purpose |
|-------|---------|---------|
| `k256` | 0.13.4 | secp256k1 + BIP340 Schnorr |
| `bip32` | 0.5.3 | HD key derivation |
| `bip39` | 2.2.2 | Mnemonic generation & seed derivation |
| `bitcoin_hashes` | 0.20.0 | SHA256, SHA256d ; HMAC-SHA256 (le PBKDF2 est écrit à la main dans `crypto.rs`) |
| `chacha20poly1305` | 0.10 | Seed chiffré au repos |
| `zeroize` | 1 | Effacement des secrets |
| `qrcode` | 0.14.1 | Génération QR, derrière la feature `std` — sur cible, `draw_qr` tombe sur un placeholder |

`wallet-core` doit rester `#![no_std]` — pas de `std`, pas d'`alloc`.

## Rust idioms (edition 2024)

- **Let chains** — utiliser `if let Some(a) = x && let Some(b) = y` plutôt que des `if let` imbriqués
- **Erreurs `no_std`** — enums d'erreur concrètes avec `impl fmt::Display` + `From` pour le `?`. Pas d'`anyhow`/`thiserror`
- **Pas d'alloc par défaut** — tableaux stack avec const generics, types par référence
- **Clippy** — `deny(clippy::correctness)`, `warn(clippy::perf)`, `warn(clippy::pedantic)` sélectivement
- **Const fn** — stable pour types primitifs, utile pour tables/constantes calculées à compile-time

## Architecture

Three crates in the workspace:

- **`wallet-core`** — `#![no_std]` library. Machine à états `ColdWallet` (`state.rs`), toute la logique Bitcoin (`psbt.rs`, `signing.rs`, `sighash.rs`, `derive.rs`), la crypto at-rest (`crypto.rs`, `storage.rs`), et `draw_ui` générique sur `DrawTarget<Color=Rgb565>`. Zéro connaissance hardware : la persistance est injectée par closure `persist(&blob)`, l'entropie arrive dans les événements.
- **`wallet-sim`** — Desktop simulator (`std`, SDL2), fenêtre 800×480 RGB565 (`.scale(1)`, pas de scaling HiDPI). Persistance réelle : `~/.config/cold-wallet/wallet.bin`, écriture atomique (tmp → fsync → rename → fsync dir). Fausse microSD : `~/.config/cold-wallet/sd/` (listing SignScan, `*-signed.psbt`, `descriptor.txt`). Entropie : `getrandom`. Pas de webcam.
- **`wallet-h747`** *(à créer)* — bare-metal M7. Le portage = remplacer ce seul crate.

**Règle de portage :** tout ce qui est hardware-dépendant (stockage, écran, tactile, timer, RNG) vit dans `wallet-sim` ou `wallet-h747`. `wallet-core` ne contient aucune dépendance plateforme.

**Display cible (carte) :** 320×240 px, RGB565, écran SPI. Le simulateur reste en 800×480 jusqu'au re-layout de l'UI (B.7 de la roadmap).

## Documents de pilotage

- `REVIEW-2026-08-14.md` — la revue complète : défauts F-01 à F-06, modèle de sécurité, portage, matériel. Le code n'a pas changé depuis : tout y est encore exact.
- `ROADMAP.md` — le plan décidé (cadre, phases, hors-périmètre assumé). Suivre cet ordre ; ne pas ouvrir une phase hors séquence sans raison.

When adding UI states: add a variant to `AppState` in `wallet-core/src/state.rs` and a match arm in `draw_ui`. Keep all crypto and wallet logic inside `wallet-core`.
