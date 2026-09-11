# cold-wallet

**A Bitcoin signer that never touches the internet.**

An air-gapped Taproot wallet written in Rust. The keys live on a device with no
Wi-Fi, no Bluetooth, no USB — a signed transaction is all that ever crosses the
gap, as a file on a microSD card.

```
   HOT SIDE (Sparrow)                     COLD SIDE (this wallet)
┌────────────────────────┐             ┌──────────────────────────────┐
│ import descriptor.txt  │             │ export descriptor (Settings) │
│ build unsigned PSBT    │  SD folder  │  load *.psbt → review        │
│ export *.psbt          │ ──────────► │  (amounts, fee, change)      │
│                        │             │  sign (BIP340 key-path)      │
│ load *-signed.psbt     │ ◄────────── │  write *-signed.psbt         │
│ broadcast signed tx    │   SD folder │                              │
└────────────────────────┘             └──────────────────────────────┘

              the private key never leaves the cold side
```

## What it actually is

A `no_std` Rust core (`wallet-core/`) holding **everything** — state machine,
PSBT parsing, derivation, signing, crypto-at-rest, UI — rendered through
`embedded-graphics` on a generic RGB565 draw target. Today it runs as a desktop
simulator (`wallet-sim/`, 800×480, SDL2) where a local folder plays the
microSD; the intended home is a bare STM32H747I-DISCO board, and the core
already cross-compiles clean for `thumbv7em-none-eabihf` in CI.

No framework, no wallet SDK: the PSBT parser, the bech32m encoder, PBKDF2,
HMAC-SHA256, the sighash preimage and the descriptor checksum are all written
here, bounded and tested.

## Bitcoin, exactly one flavor

Taproot, key-path only, **testnet4** (testnet3 is deprecated). Derivation scans the receive and change
windows of `m/86'/1'/0'` (index 0..19 each) and yields `tb1p…` addresses
through a hand-written bech32m (checked against the BIP350 vectors). Transactions
travel as **BIP174 PSBTs**: the parser accepts at most 5 inputs, 8 outputs and
4096 bytes, lives entirely on the stack, and allocates nothing. The unsigned
transaction is preserved byte-for-byte from scan to signature.

Signing is BIP341 key-path: the five hash aggregates, the `H_TapTweak` of the
internal key, a BIP340 Schnorr signature from `k256` — with touch-derived
auxiliary randomness, so the same message never signs twice identically. Only
SIGHASH_DEFAULT is signed; explicit sighash types are refused.

## Trust nothing

The review screen re-derives what the PSBT *claims*:

- the witness UTXO's scriptPubKey **must** be our own P2TR output — a mismatch
  aborts the signature;
- change is detected by matching each output against the wallet's own derived
  output keys across the whole window, never by reading a change flag the host
  could have lied about; unrecognized outputs are shown as plain sends;
- sighash types other than SIGHASH_DEFAULT are refused;
- fees above 25 % of the input sum — or larger than the amount sent — are
  flagged on screen before confirmation.

## Keys at rest

The seed (BIP39, 24 words, optional passphrase) and its entropy are sealed in a
ChaCha20-Poly1305 blob whose key is stretched from a 6-digit PIN through
PBKDF2-HMAC-SHA256 — 1,000,000 iterations, written from scratch, checked
against RFC vectors. The version byte and salt are bound as AAD, so a blob
cannot be downgraded or resalted without breaking its tag.

Three wrong PINs lock the wallet. The failure counter is persisted *before*
the PIN is checked (write-ahead, fsync), the comparison is constant-time, and
`write_volatile` + `Drop` scrub the secrets — including the BIP39 word table —
when they leave scope.

## Honesty section

This is an educational project. **Not audited. Do not store real funds** — the
build is testnet for that reason.

| Works | Missing |
|---|---|
| Descriptor export (text + QR, BIP380 checksum) | **QR decode** — the SD folder is the only channel |
| First real testnet4 transaction signed and **broadcast** end-to-end (bdk-verified) | Wipe after lockout; passphrase re-asked at unlock |
| SD-folder exchange in the sim (load `*.psbt`, write `*-signed.psbt`) | The hardware port (custom H753 + SPI screen board, not started) |
| Derivation window (receive + change, index 0..19) | No hot-side tool other than Sparrow (fine) |
| `no_std` + thumbv7em build in CI | Known limits: host-provided input amounts (F-06), no mnemonic re-check at creation (F-05) |

The full review lives in `REVIEW-2026-08-14.md`; the plan, in `ROADMAP.md`.

## Run it

```sh
cargo run -p wallet-sim        # needs SDL2; state in ~/.config/cold-wallet
                               # SD folder: ~/.config/cold-wallet/sd/
```

Welcome → *New wallet* (24 words, touch entropy) → set a PIN → *Settings →
Descriptor* (or the exported `descriptor.txt`) → import it in Sparrow (see
below) → export a PSBT into the SD folder → *Sign* → pick the file → review →
confirm → the `*-signed.psbt` lands next to it, ready to load and broadcast in
Sparrow.

99 tests: `cargo test`, quality gates: `cargo clippy -- -D warnings`.

## Author

Sonam — [github.com/scrumier](https://github.com/scrumier)
