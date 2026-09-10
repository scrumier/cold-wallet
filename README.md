# cold-wallet

**A Bitcoin signer that never touches the internet.**

An air-gapped Taproot wallet written in Rust. The keys live on a device with no
Wi-Fi, no Bluetooth, no USB — the only thing that ever crosses the gap is a
transaction, in and out, as pixels.

```
   HOT SIDE (online)                      COLD SIDE (this wallet)
┌────────────────────────┐             ┌──────────────────────────────┐
│ build unsigned PSBT    │    QR in    │  decode → review on screen   │
│ (Sparrow, custom tool) │ ──────────► │  (amounts, fee, change)      │
│                        │             │  sign (BIP340 key-path)      │
│ broadcast signed tx    │ ◄────────── │  emit signed PSBT as QR      │
└────────────────────────┘    QR out   └──────────────────────────────┘

              the private key never leaves the cold side
```

## What it actually is

A `no_std` Rust core (`wallet-core/`) holding **everything** — state machine,
PSBT parsing, derivation, signing, crypto-at-rest, UI — rendered through
`embedded-graphics` on a generic RGB565 draw target. Today it runs as a desktop
simulator (`wallet-sim/`, 800×480, SDL2); the intended home is a bare
STM32H747I-DISCO board, and the core already cross-compiles clean for
`thumbv7em-none-eabihf` in CI.

No framework, no wallet SDK: the PSBT parser, the bech32m encoder, PBKDF2,
HMAC-SHA256 and the sighash preimage are all written here, bounded and tested.

## Bitcoin, exactly one flavor

Taproot, key-path only, mainnet. Derivation is pinned to `m/86'/0'/0'/0/0`
and yields a `bc1p…` address through a hand-written bech32m. Transactions
travel as **BIP174 PSBTs**: the parser accepts at most 5 inputs, 8 outputs and
2048 bytes, lives entirely on the stack, and allocates nothing.

Signing is BIP341 key-path: the five hash aggregates, the `H_TapTweak` of the
internal key, a BIP340 Schnorr signature from `k256` — with touch-derived
auxiliary randomness, so the same message never signs twice identically.

## Trust nothing

The review screen re-derives what the PSBT *claims*:

- the witness UTXO's scriptPubKey **must** be our own P2TR output — a mismatch
  aborts the signature;
- change is detected by re-deriving the output key ourselves, never by reading
  a change flag the host could have lied about; unrecognized outputs are shown
  as plain sends;
- sighash is refused unless it is `ALL`;
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

This is an educational project. **Not audited. Do not store real funds.**
What is real and what is still a sketch:

| Works | Missing |
|---|---|
| Sign PSBTs end-to-end (tests re-verify the Schnorr sig) | **QR decode** — the sim injects a synthetic PSBT on click |
| Seed creation, restore, PIN, lockout, at-rest crypto | Any **hot-side tool** (nothing builds PSBTs or broadcasts yet) |
| Bounded parser, re-derived change, fee guards | Multi-address (one index; a `/1/0` change shows as a send) |
| `no_std` + thumbv7em build in CI | Known parser quirks, documented in `REVIEW-2026-08-14.md` |

The roadmap has pivoted: the QR *input* channel is deferred in favor of a
**microSD** file exchange (read `*.psbt`, write `*-signed.psbt`), plus testnet
support and a `tr(...)` descriptor export. See `ROADMAP.md`.

## Run it

```sh
cargo run -p wallet-sim        # needs SDL2; state persists in ~/.config/cold-wallet
```

Welcome → *New wallet* (24 words, touch entropy) → set a PIN → *Sign* → click
the viewfinder to inject a PSBT → review → confirm → scan the QR back.

83 tests: `cargo test`, quality gates: `cargo clippy -- -D warnings`.

## Author

Sonam — [github.com/scrumier](https://github.com/scrumier)
