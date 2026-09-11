# Roadmap — cold-wallet

**Cadre retenu** (décidé le 14/08/2026, mis à jour le 11/09/2026) :
- **Objectif** : portfolio / démo montrable sur vrai matériel. Pas de fonds réels significatifs, donc pas d'élément sécurisé.
- **Sécurité** : wipe après N échecs **et** passphrase redemandée au déverrouillage (le seed n'est plus stocké). Pas implémenté — c'est la phase 2.
- **Canal E/S** : microSD. Implémenté dans le simulateur.
- **Réseau** : **testnet4** (testnet3 est déprécié).

**État au 11/09/2026** : le jalon phase 3 est **bouclé**. Une vraie transaction testnet4 a été signée par le wallet et diffusée :

```
txid 84c9fb8af8ffe8f237ba56fa07b57cdf64c21ac1f40a0de64313aad3f9e78c2f
https://mempool.space/testnet4/tx/84c9fb8af8ffe8f237ba56fa07b57cdf64c21ac1f40a0de64313aad3f9e78c2f
```

Chaîne validée de bout en bout : descriptor exporté → importé et lu par **bdk-cli** (implémentation indépendante) → adresses dérivées identiques → PSBT construit par bdk → chargé, revu, signé par le simulateur → PSBT signé finalisé par bdk → diffusé. Le jalon a révélé et corrigé un bug d'interopérabilité : `PSBT_IN_TAP_INTERNAL_KEY` est `0x17` (BIP371), pas `0x12`.

---

## Fait (croché, à ne pas casser)

- [x] **Phase 0** — CLAUDE.md réécrit et véridique, limites PSBT alignées (`MAX_PSBT_RAW` 4096, const-asserts).
- [x] **Phase 1** — F-01 (SIGHASH_DEFAULT seul), F-02 (tx non signée préservée octet pour octet), F-03 (une seule constante dérivée), F-04 (fenêtre de dérivation receive `0/0..19` + change `1/0..19`), F-06 (documenté).
- [x] **Phase 3** — testnet4 (HRP `tb`, coin `1'`), descriptor BIP386 avec checksum BIP380 (testé contre les vecteurs), canal microSD dans le simulateur (listing, lecture `*.psbt`, écriture `*-signed.psbt`, `descriptor.txt`), **jalon Sparrow bouclé via bdk-cli** (voir ci-dessus).
- [x] Test d'intégration du parcours complet (création → PIN → persistance → redémarrage KDF → descriptor → signature deux index) — tourné à chaque session, jetable. **À rendre permanent.**

## Phase 2 — Le modèle de sécurité · ~4 jours · **à faire**

- [ ] **Format disque v4 : ne stocker que l'entropie.** Le seed 64 octets disparaît du blob, remplacé par les 32 octets d'entropie. *~1 j*
- [ ] **Passphrase au déverrouillage.** PIN → passphrase → dérivation du seed en RAM. L'écran `EnterPassphrase` existe déjà. *~1 j*
- [ ] **Baisser les itérations PBKDF2** (~200 000) une fois la passphrase porteuse d'entropie. *~0,5 j*
- [ ] **Précalculer les midstates ipad/opad du HMAC** (le code reconstruit un `HmacEngine` complet à chaque itération, ×2 pour rien). *~0,5 j*
- [ ] **Wipe après 3 échecs.** Écraser le blob, écran d'avertissement au 2ᵉ échec, délai croissant. *~1 j*

## Phase 2bis — Les tests manquants · ~1 j · **à faire**

Identifiés le 11/09 : le compteur (99) est correct, les trous sont ciblés.

- [ ] **Test d'intégration permanent** : rendre le parcours complet de bout en bout un test du dépôt (il est refait jetablement à chaque session). Ajouter le flux Restore complet (24 mots → même adresse).
- [ ] **Vecteurs sighash BIP341 officiels** : les sighash attendus publiés avec le BIP — la preuve bit-exact avec Bitcoin Core.
- [ ] **Tests de bornes du parser** : 6 inputs refusés, 9 outputs refusés, scriptPubKey 35 o refusé, tx > `MAX_TX_RAW` refusée.
- [ ] **Mini-fuzz** : mutations déterministes d'un PSBT valide (10 k), aucune panique.
- [ ] **PSBT "étranger"** riche (derivations BIP32, clés inconnues) : ignoré proprement, signature qui passe.

## Phase 4 — Génération de QR en `no_std` · ~2 jours · **à faire**

- [ ] Le crate `qrcode` est derrière la feature `std` : sur la carte, `draw_qr` tombe sur le placeholder. Encoder `no_std` à buffer fixe, ou assumer l'écran-only.

---

## Voie B — Le portage matériel · **réorientée le 11/09**

Décision : **abandonner la DISCO** (140 €, écran MIPI-DSI sans driver Rust : 5-15 j de FFI = le long pole, et du travail qui n'apprend rien sur Bitcoin). La carte est **dessinée par nous** :

- **MCU : STM32H753VIT6 en LQFP100** — soudable à la main (drag soldering), et il embarque **SHA-256 matériel** : le PBKDF2 du PIN tombe de ~10 s à ~0,2 s sur cible.
- **Écran : SPI 320×240 RGB565** (ILI9341/ST7735 — drivers Rust existants). Framebuffer 150 Ko : tient en RAM interne, **pas de SDRAM**.
- **microSD en SPI** (le même canal que le simulateur).
- **PCB 4 couches** (JLCPCB, ~30 € les 5), secrets en DTCM exclusivement.
- Tactile : résistif (XPT2046, driver existant) ou boutons physiques mappés sur des zones — à décider au design.

- [ ] **B.0 · Dev board en banc d'essai.** WeAct STM32H743 core board (~20 €, déjà soudé) : développer Embassy + écran SPI + SD dessus pendant que le PCB fabrique. *~2 j*
- [ ] **B.1 · Schéma KiCad + BOM.** Copier les références WeAct/Nucleo (boot, HSE, régulateur), écran SPI + SD + SWD + USB-C + points de test. *~1 semaine d'apprentissage*
- [ ] **B.2 · Routage 4 couches + fabrication JLCPCB + assemblage** (JLC assembly pour MCU/passifs ; connecteurs à la main). *~2-3 semaines de cycle*
- [ ] **B.3 · Bring-up** : probe-rs + defmt, blink, horloge. *~1 j*
- [ ] **B.4 · Écran SPI + microSD + TRNG** sur la carte custom. *~2 j*
- [ ] **B.5 · Persistance flash A/B** (secteurs, journal append-only pour le compteur d'échecs). *~4 j*
- [ ] **B.6 · Mesurer le PBKDF2 réel (avec accélérateur) et ajuster les itérations.** *~0,5 j*
- [ ] **B.7 · Re-layout de l'UI** : 800×480 → 320×240 (le draw est générique, c'est du layout). *~1-2 j*

---

## Hors périmètre, assumé

| Écarté | Pourquoi |
|---|---|
| Caméra + décodage QR | Semaines de vision par ordinateur qui n'apprennent rien sur Bitcoin. La microSD fait le travail. |
| QR animé BC-UR | Sans scan caméra, sans objet. |
| Dual-core M7 + M4 | Coût de complexité, frontière de sécurité nulle. |
| Élément sécurisé (ATECC608B) | Aucun intérêt sans fonds réels : le wallet n'est pas utilisé avec de la vraie valeur. Revenir au moment où ça change. |
| Testnet3 | Déprécié partout. Testnet4. |
| STM32H747I-DISCO | 140 € + le long pole DSI. Remplacée par la carte custom H753 + SPI (voir voie B). |

---

## Cette semaine

1. Phase 2 (modèle de sécurité) — c'est ce qui transforme la démo en wallet défendable. F-05 (vérification de la mnémonique) d'abord : on n'efface jamais un wallet dont le backup n'a pas été vérifié.
2. Phase 2bis (tests manquants) — une journée, elle verrouille tout le reste.
3. Commander le dev board + écran SPI + microSD, et commencer B.0.
