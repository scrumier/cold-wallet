# Roadmap — cold-wallet

**Cadre retenu** (décidé le 14/08/2026) :
- **Objectif** : portfolio / démo montrable sur vrai matériel. Pas de fonds réels significatifs, donc pas d'élément sécurisé ni de PCB custom.
- **Sécurité** : wipe après N échecs **et** passphrase redemandée au déverrouillage (le seed n'est plus stocké).
- **Canal E/S** : microSD d'abord. Caméra et QR animé repoussés hors périmètre v1.

Estimations en jours-homme à temps plein, à diviser par ta disponibilité réelle.

---

## Le point de structure : deux voies parallèles

Le portage matériel touche `wallet-h747` (à créer) et **ne dépend d'aucune** des corrections Bitcoin qui touchent `wallet-core`. Si tu as une échéance de démo, lance la voie B dès que la phase 0 est faite — le bring-up matériel a la plus grosse incertitude, c'est lui qui doit démarrer tôt.

```
Phase 0 ─┬─ Voie A (wallet-core) : phases 1 → 2 → 3 → 4     ~4 semaines
         └─ Voie B (wallet-h747) : phase 5                   ~5-8 semaines
                                        └─ convergence : phase 6
```

L'ordre à l'intérieur de chaque voie, lui, est contraignant.

---

## Phase 0 — Assainir la base · ~1 jour

À faire avant tout le reste : c'est ce qui empêche les erreurs de se propager dans chaque session suivante.

- [ ] **Réécrire `CLAUDE.md`.** Retirer `nokhwa`/webcam (n'existe pas), corriger « LTDC » → MIPI-DSI, retirer la promesse multi-compte et `m/86'/0'/0'/0/n`, corriger « scale ×2 » → `.scale(1)`.
- [ ] **Y inscrire les deux règles de portage** décidées : mono-cœur M7 (le M4 reste en sommeil), et *aucun secret en SDRAM externe* — seed, PIN, clés dérivées vivent en DTCM uniquement.
- [ ] **Aligner les limites de taille** (F-03) : une seule constante entre `WalletEvent::PsbtScanned`, `MAX_PSBT_RAW` et `MAX_INPUTS`, avec un `const _: () = assert!(…)` qui casse la compilation si elles divergent. Avec la microSD, tu peux monter franchement (4–8 Ko).

---

# Voie A — Rendre le signer correct et utile

## Phase 1 — Corriger les défauts de signature · ~5 jours

Dans cet ordre : F-05 en premier parce que le wipe de la phase 2 en dépend (on n'efface pas un wallet dont le backup n'a jamais été vérifié).

- [ ] **F-05 · Vérification de la mnémonique à la création.** Après l'affichage des 24 mots, redemander 3 ou 4 mots tirés au hasard. Réutiliser l'écran `RestoreWallet` existant avec son autocomplétion — le gros du code est déjà écrit. *~1 j*
- [ ] **F-01 · Type de sighash.** Le plus simple et le plus sûr : refuser `sighash_type = Some(1)` au même titre que les autres types non supportés, et ne signer que `None`/`Some(0)`. Si tu veux faire propre, propager le type dans le préimage et émettre 65 octets. *~0,5 j*
- [ ] **F-02 · Préserver le PSBT d'origine.** Garder le slice brut de `PSBT_GLOBAL_UNSIGNED_TX` (les `tx_start`/`tx_end` sont déjà calculés dans `parse`, il suffit de ne plus les jeter) et le réémettre tel quel. Mieux : conserver le buffer PSBT complet et n'y insérer que les `PSBT_IN_TAP_KEY_SIG`. *~1,5 j*
- [ ] **F-04 · Fenêtre de dérivation.** Balayer un gap fixe (receive `0/0..20`, change `1/0..20`) pour classer les outputs à la revue **et** pour matcher les inputs à la signature. C'est ce qui empêche l'écran de revue d'afficher ton propre change comme un envoi à un inconnu. *~1,5 j*
- [ ] **F-06 · Documenter** que les montants d'input viennent de l'hôte et ne sont pas vérifiables offline. *~10 min*
- [ ] Tests : un PSBT avec change sur `1/0`, un PSBT multi-input sur deux index différents, un PSBT qui déclare `SIGHASH_SINGLE`.

## Phase 2 — Le modèle de sécurité · ~4 jours

- [ ] **Format disque v4 : ne stocker que l'entropie.** Le seed 64 octets disparaît du blob, remplacé par les 32 octets d'entropie. Le blob passe de 143 à ~111 octets. *~1 j*
- [ ] **Passphrase au déverrouillage.** Le flux devient PIN → passphrase → dérivation du seed en RAM. L'écran `EnterPassphrase` existe déjà, il faut le brancher sur le chemin de déverrouillage et pas seulement sur la création. *~1 j*
- [ ] **Baisser les itérations PBKDF2.** Une fois que la passphrase porte l'entropie, 1 000 000 d'itérations n'ont plus de justification — vise ~200 000 pour rester sous ~2 s sur le M7. *~0,5 j*
- [ ] **Précalculer les midstates ipad/opad du HMAC.** Le code reconstruit un `HmacEngine` complet à chaque itération, ce qui double le travail pour rien. Gain immédiat de ×2. *~0,5 j*
- [ ] **Wipe après 3 échecs.** Écraser le blob (zéros, puis effacement du fichier / du secteur), écran d'avertissement explicite dès le 2ᵉ échec, et un délai croissant entre essais. *~1 j*

## Phase 3 — Le canal microSD et le bouclage complet · ~6 jours

C'est la phase qui transforme le projet en objet démontrable.

- [ ] **Signet ou testnet.** Paramétrer le HRP bech32 (`tb`) et le coin type BIP86 (`m/86'/1'/…`). Sans ça tu ne peux tester avec aucun vrai logiciel sans risquer de vrais fonds. *~1 j*
- [ ] **Export du descriptor.** `tr([<fingerprint>/86h/1h/0h]<xpub>/<0;1>/*)` écrit sur la carte, plus affiché en QR. **C'est le chaînon manquant** : sans lui, aucun wallet de surveillance ne peut construire de PSBT pour toi, et la boucle « online → PSBT » n'a jamais été bouclée une seule fois. *~1,5 j*
- [ ] **Lecture / écriture de PSBT sur fichier.** Convention simple : lire `*.psbt` à la racine, écrire `<nom>-signed.psbt`. *~1 j*
- [ ] **Côté simulateur, monter un répertoire local comme fausse carte SD**, avec un écran de sélection de fichier. *~1 j*
- [ ] 🎯 **Jalon : signer une vraie transaction signet de bout en bout avec Sparrow.** Import du descriptor → construction du PSBT → fichier → signature → fichier → diffusion. C'est le test qui valide rétroactivement les phases 1 à 3, et qui fera apparaître les bugs que les tests unitaires ne voient pas. *~1,5 j*

## Phase 4 — Génération de QR en `no_std` · ~2 jours

- [ ] Le crate `qrcode` est derrière la feature `std` : sur la carte, `draw_qr` tombe aujourd'hui sur le placeholder. Il faut soit un encodeur `no_std` à buffer fixe, soit `embedded-alloc` (mais un allocateur sur un appareil qui ne doit jamais paniquer se paie).
- [ ] Nécessaire pour afficher l'adresse de réception **et** le descriptor sur le matériel.

---

# Voie B — Le portage H747

## Phase 5 — `wallet-h747` · ~5 à 8 semaines

Ordonné par risque décroissant : le 5.4 est le seul dont l'estimation peut doubler, attaque-le tôt pour le savoir tôt.

- [ ] **5.1 · Bring-up mono-cœur M7.** `probe-rs` + `defmt`, un blink, la horloge à 480 MHz. Le M4 reste en sommeil. *~2 j*
- [ ] **5.2 · MPU, caches et carte mémoire.** Configurer avant d'avoir du code à déboguer par-dessus — c'est l'origine numéro un des « ça marche en debug, pas en release ». Définir les sections : framebuffer et buffers PSBT en SDRAM, **secrets en DTCM exclusivement**. *~2 j*
- [ ] **5.3 · SDRAM externe (FMC).** *~3 j*
- [ ] **5.4 · Écran MIPI-DSI.** ⚠️ Le long pole. Chaîne LTDC → DSI Host → contrôleur de dalle. `embassy-stm32` n'a pas de driver DSI : soit tu l'écris, soit tu fais du FFI vers le BSP C de ST. **Pour une démo, le FFI est le choix rationnel** — le driver DSI en Rust est un projet en soi et n'ajoute rien à la démonstration. *~5 à 15 j*
- [ ] **5.5 · Tactile capacitif** (FT5336 en I2C). Simple, et ça débloque le test de toute l'UI. *~1 j*
- [ ] **5.6 · microSD** (SDMMC + FAT32 via `embedded-sdmmc`). *~4 j*
- [ ] **5.7 · TRNG** pour l'entropie de création et l'`aux_rand` BIP340. *~0,5 j*
- [ ] **5.8 · Persistance flash A/B.** Secteurs de 128 Ko, écriture par mots de 256 bits non réinscriptibles : deux secteurs en ping-pong, plus un journal append-only pour le compteur d'essais. Une coupure pendant l'effacement ne doit pas détruire le wallet. *~4 j*
- [ ] **5.9 · Mesurer le PBKDF2 réel sur cible** et réajuster les itérations pour tenir sous ~2 s. *~0,5 j*

---

## Phase 6 — Convergence et finition démo · ~3 jours

- [ ] Faire tourner le flux complet sur la carte : déverrouillage PIN + passphrase → lecture du PSBT sur SD → revue à l'écran → signature → écriture du fichier signé.
- [ ] Écran « À propos » avec version et hash de commit.
- [ ] README avec une capture ou une vidéo du flux complet, et une section « limites connues » honnête — c'est ce qui distingue un portfolio crédible d'une démo qui surpromet.
- [ ] Garder le mainnet derrière un avertissement explicite tant qu'il n'y a pas d'audit.

---

## Hors périmètre, assumé

Décidé, pas oublié — à écrire tel quel dans le README :

| Écarté | Pourquoi |
|---|---|
| Caméra + décodage QR | Plusieurs semaines de vision par ordinateur qui n'apprennent rien sur Bitcoin. La microSD fait le même travail. |
| QR animé BC-UR | Sans scan caméra, sans objet. |
| Dual-core M7 + M4 | Coût de complexité réel, frontière de sécurité nulle : les deux cœurs voient la même mémoire. |
| Élément sécurisé (ATECC608B) | Implique une carte custom. Hors périmètre pour un portfolio. |
| PCB custom | Idem. Si tu y viens un jour : écran SPI 320×240 → plus de SDRAM → STM32H743VIT6 en LQFP100, 4 couches, soudable à la main. |
| Multi-compte | La fenêtre de dérivation de F-04 couvre le besoin réel. Retirer le bouton mort « Comptes » ou le griser. |

---

## Cette semaine

1. Phase 0 en entier (~1 j).
2. F-05, la vérification de mnémonique (~1 j) — c'est ce qui protège des fonds dès aujourd'hui.
3. Commander ce qu'il manque pour la voie B et faire le 5.1 (~2 j), pour découvrir tôt les surprises de toolchain.
