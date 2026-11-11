# ligrivsstore

Gestionnaire de mots de passe du projet **KEEPASS** : applications Windows (avec extension Chrome et Edge) et Android, puis iPhone, iPad et Mac. Chaque terminal garde son coffre chiffré et le synchronise avec le serveur « coffre » hébergé sur l'infrastructure Zanzibar.

> **État : jalon 1 en cours (semaine 2 sur 5).** Le noyau, l'outil de recette, les tests et l'intégration continue sont en place et recettés (jalon 0). L'application Windows crée, ouvre et synchronise le coffre entre plusieurs PC, se verrouille seule, copie sans laisser de trace et restaure ses sauvegardes. L'extension et le remplissage arrivent dans les semaines suivantes.

## Principes

- **Format ouvert** : les coffres sont des fichiers KDBX 4, lisibles par KeePassXC, KeePassDX, KeePassium… Ainsi, l'utilisateur n'est jamais captif de l'application.
- **Chiffrement sur le terminal** : AES-256, dérivation de clé Argon2id (32 Mio), phrase de passe et fichier clé. Le serveur ne voit que des fichiers chiffrés.
- **Hors ligne d'abord** : chaque terminal travaille sur sa copie locale. La synchronisation fusionne les modifications de tous les terminaux, sans perte.
- **Un seul noyau** : tout ce qui touche aux secrets est écrit une fois, en Rust, testé, puis appelé par chaque application.
- **Aucune télémétrie**.

## Contenu du dépôt

| Dossier | Contenu |
|---|---|
| `crates/core` | Noyau `ligrivsstore-core` : coffre, contrôle d'en-tête, dérivation, stockage, fusion, synchronisation, générateur |
| `crates/cli` | Outil `lgs`, pour le développement, la recette et le diagnostic (ce n'est pas l'application) |
| `crates/app` | Logique de l'application de bureau `ligrivsstore-app` : session, synchronisation, pilote (verrouillage automatique, échéances), réglages, messages et erreurs de l'interface (sans Tauri, testée avec le reste) |
| `crates/win` | Intégration à Windows `ligrivsstore-win` : verrouillage de session, mise en veille, presse-papiers protégé ; seul paquet où du code `unsafe` est admis (décision 0011) |
| `apps/windows` | Application Windows : interface Svelte (`src`), coquille Tauri (`src-tauri`), cadre d'isolation (`isolation`) |
| `fuzz` | Cibles de tests aléatoires guidés (cargo-fuzz), lancées chaque semaine |
| `scripts` | Banc WebDAV local (Apache derrière un relais HTTPS), tests du serveur et scénario de recette de bout en bout |
| `server/coffre` | Fichiers du service « coffre » revus par la conversation « infra » (11 novembre 2026) : fiche de déploiement et configuration |
| `docs` | Architecture, décisions, plan de recette |
| `.github` | Intégration continue (format, analyse, tests, interopérabilité, licences, vulnérabilités) |

## Démarrer

Prérequis : [rustup](https://rustup.rs). La version de Rust est fixée par `rust-toolchain.toml` et installée automatiquement.

```bash
cargo build --workspace
cargo test --workspace            # tests unitaires, de fusion, de synchronisation simulée, aléatoires
```

Les tests d'interopérabilité (KeePassXC) et de synchronisation réelle (Apache) s'exécutent quand leurs outils sont présents. Sous Linux, le dossier [docs/recette-j0.md](docs/recette-j0.md) en donne la marche complète :

```bash
sudo apt-get install keepassxc apache2 apache2-utils openssl busybox
sudo scripts/banc-webdav.sh demarrer        # Apache « coffre » derrière un relais HTTPS
sudo scripts/tests-serveur.sh               # 63 tests du serveur, par le relais
set -a; . /tmp/lgs-banc-webdav/env; set +a
cargo test --workspace
scripts/scenario-synchro.sh
sudo scripts/banc-webdav.sh arreter
```

### Application Windows

Prérequis supplémentaires : [Node.js](https://nodejs.org) 22.12 ou plus récent, et WebView2 (déjà présent sous Windows 11).

```powershell
cd apps\windows
npm ci                    # dépendances de l'interface, versions figées
npm run check             # vérification de l'interface (svelte-check)
npm run tauri dev         # application en mode développement
npm run tauri build       # installateur dans src-tauri\target\release\bundle\nsis
```

L'intégration continue produit aussi l'installateur à chaque demande de fusion : fichier `ligrivsstore-installateur-windows` de l'exécution, conservé 30 jours. Il n'est pas encore signé : Windows SmartScreen avertit à l'installation.

## L'outil `lgs`

Les secrets ne passent jamais par la ligne de commande. Ils sont lus dans des variables d'environnement : `LGS_PASSWORD` (coffre), `LGS_WEBDAV_PASSWORD` (serveur) et `LGS_ENTRY_PASSWORD` (entrée).

```bash
read -rsp "Phrase de passe du coffre : " LGS_PASSWORD && echo && export LGS_PASSWORD
lgs new coffre.kdbx --calibrate-ms 1000      # crée un coffre (Argon2id calibré)
lgs add coffre.kdbx --title Banque --url https://banque.exemple --username hermann --generate 24
lgs list coffre.kdbx
lgs show coffre.kdbx Banque --reveal
lgs sync coffre.kdbx --url https://coffre.ligrivs.com/dav/hermann/coffre.kdbx --user hermann
lgs sync coffre.kdbx --url … --user hermann --new-credentials   # après un refus d'identifiants
lgs info coffre.kdbx                         # format et dérivation, sans clé
lgs backups coffre.kdbx                      # sauvegardes locales
```

Fichier clé : `lgs keyfile cle.keyx` en crée un au format XML 2.0 de KeePass, celui de KeePassXC. Il s'utilise ensuite avec `-k cle.keyx` sur chaque commande. Gardez-en une copie à part : sans lui, le coffre ne s'ouvre plus.

## Feuille de route

| Jalon | Contenu |
|---|---|
| J0 — Fondations | Noyau, outil de recette, tests, intégration continue (recetté) |
| J1 — Windows et extension (**en cours**) | Application Tauri ; extension Chrome et Edge (messagerie native, appairage) ; correspondance des domaines ; phrases de passe ; enregistrement des nouveaux identifiants |
| J2 — Android | Application Kotlin (liaisons UniFFI) ; service de remplissage ; biométrie |
| J3 — Durcissement et bêta | Revue de sécurité interne ; conflits multi-terminaux ; bêta familiale |
| Ensuite | iPhone et iPad, Mac et Safari (dès qu'un Mac est disponible) ; Firefox ; audit externe ; vente dans les stores |

Les choix sont expliqués dans [docs/architecture.md](docs/architecture.md) et dans [docs/decisions](docs/decisions).

## Licence

Logiciel propriétaire : voir [LICENSE](LICENSE). Les dépendances sont sous licences permissives, contrôlées par `cargo-deny`. Seule exception : cinq paquets sous MPL-2.0 venus de Tauri, admis un à un (décision 0010) ; un seul figure dans le programme livré, sans modification.
