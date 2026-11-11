# ligrivsstore

Gestionnaire de mots de passe du projet **KEEPASS** : applications Windows (avec extension Chrome et Edge) et Android, puis iPhone, iPad et Mac. Chaque terminal garde son coffre chiffré et le synchronise avec le serveur « coffre » hébergé sur l'infrastructure Zanzibar.

> **État : jalon 0 (fondations).** Le dépôt contient le noyau partagé, un outil de recette en ligne de commande, les tests et l'intégration continue. Les applications arrivent aux jalons suivants.

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
| `fuzz` | Cibles de tests aléatoires guidés (cargo-fuzz), lancées chaque semaine |
| `scripts` | Banc WebDAV local et scénario de recette de bout en bout |
| `server/coffre` | Copie de référence du service « coffre » (fiche de déploiement et configuration) |
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
sudo apt-get install keepassxc apache2 apache2-utils
sudo scripts/banc-webdav.sh demarrer
set -a; . /tmp/lgs-banc-webdav/env; set +a
cargo test --workspace
scripts/scenario-synchro.sh
sudo scripts/banc-webdav.sh arreter
```

## L'outil `lgs`

Les secrets ne passent jamais par la ligne de commande. Ils sont lus dans des variables d'environnement : `LGS_PASSWORD` (coffre), `LGS_WEBDAV_PASSWORD` (serveur) et `LGS_ENTRY_PASSWORD` (entrée).

```bash
read -rs LGS_PASSWORD && export LGS_PASSWORD
lgs new coffre.kdbx --calibrate-ms 1000      # crée un coffre (Argon2id calibré)
lgs add coffre.kdbx --title Banque --url https://banque.exemple --username hermann --generate 24
lgs list coffre.kdbx
lgs show coffre.kdbx Banque --reveal
lgs sync coffre.kdbx --url https://coffre.ligrivs.com/dav/hermann/coffre.kdbx --user hermann
lgs info coffre.kdbx                         # format et dérivation, sans clé
lgs backups coffre.kdbx                      # sauvegardes locales
```

## Feuille de route

| Jalon | Contenu |
|---|---|
| J0 — Fondations | Noyau, outil de recette, tests, intégration continue (**ce dépôt**) |
| J1 — Windows et extension | Application Tauri ; extension Chrome et Edge (messagerie native, appairage) ; correspondance des domaines ; phrases de passe |
| J2 — Android | Application Kotlin (liaisons UniFFI) ; service de remplissage ; biométrie |
| J3 — Durcissement et bêta | Revue de sécurité interne ; conflits multi-terminaux ; bêta familiale |
| Ensuite | iPhone et iPad, Mac et Safari (dès qu'un Mac est disponible) ; Firefox ; audit externe ; vente dans les stores |

Les choix sont expliqués dans [docs/architecture.md](docs/architecture.md) et dans [docs/decisions](docs/decisions).

## Licence

Logiciel propriétaire : voir [LICENSE](LICENSE). Les dépendances sont toutes sous licences permissives (contrôle par `cargo-deny`).
