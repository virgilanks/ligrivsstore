# Recette du jalon 0 — fondations

Le jalon 0 livre le noyau, l'outil `lgs`, les tests et l'intégration continue. Livrable vérifiable annoncé : **tests automatiques au vert, y compris le scénario de conflit.**

## 1. Tests automatiques

Résultats du 11 novembre 2026, sur un banc Linux : Rust 1.97.0, KeePassXC 2.7.6, et Apache 2.4.58 avec la configuration revue du serveur « coffre », derrière un relais HTTPS. Après l'intégration de la revue infra, la suite complète a été lancée deux fois de suite, sans échec. L'intégration continue sur GitHub (Rust 1.99.1) est verte avant et après la revue. Après la revue : 81 tests réussis sous Linux, 80 sous Windows (un test des droits de fichiers est propre à Unix), 63 tests du serveur et le scénario (25 sur 25) sur le banc.

| Suite | Ce qui est vérifié | Tests | Résultat |
|---|---|---|---|
| Unitaires (`src/`) | En-tête strict et plafonds, politique de dérivation, calibrage, stockage atomique et sauvegardes, droits des fichiers, étiquettes HTTP, adresses refusées, règles du serveur (racine du dossier, noms temporaires, 50 Mo), autorité de certification, générateur (familles, longueur, uniformité), historique | 35 | Réussi |
| Coffre (`tests/coffre.rs`) | Aller-retour de tous les champs, KDBX 4.1 et Argon2id écrits, réglages faibles jamais écrits, mauvaise clé, en-têtes hostiles refusés en moins de 200 ms, fichier trop gros, sauvegardes lisibles | 11 | Réussi |
| Fusion (`tests/fusion.rs`) | Ajouts des deux côtés, dernière modification gagnante et historique, suppressions propagées et non ressuscitées, coffres étrangers refusés, modifications rapides et simultanées sans perte | 7 | Réussi |
| Synchronisation simulée (`tests/synchro.rs`) | Création, second terminal, modifications concurrentes, écriture entre téléchargement et envoi (412), reconnaissance de son propre envoi, étiquettes faibles, conflits sans fin, coffre distant d'une autre clé, étranger ou corrompu jamais écrasé, suppressions, suspension après un refus d'identifiants (même après redémarrage) | 13 | Réussi |
| Interopérabilité (`tests/interop_keepassxc.rs`) | Coffre du noyau lu par KeePassXC (fichier clé exigé), coffre KeePassXC (KDBX 3.1, AES-KDF) modifié par le noyau puis relu, fusion de modifications faites avec KeePassXC | 3 | Réussi |
| Serveur réel (`tests/webdav.rs`), par le relais HTTPS | Convergence de deux terminaux, 412 réel puis reprise, création conditionnelle, dossier d'un autre compte refusé par le noyau, mauvais mot de passe puis suspension, lecture par KeePassXC du coffre du serveur | 6 | Réussi |
| Aléatoires (`tests/robustesse*.rs`) | 512 cas par propriété : octets quelconques, coffres altérés, préfixes, suffixes ; mesure sur 3 000 fichiers altérés | 6 | Réussi |
| **Total** | | **81** | **Réussi** |

Contrôles complémentaires :

| Contrôle | Résultat |
|---|---|
| Tests du serveur `scripts/tests-serveur.sh`, par le relais HTTPS | 63 réussis sur 63 avec la configuration revue ; la configuration d'avant la revue donne 9 échecs (MOVE et COPY en 502, MKCOL accepté), ce qui montre que le banc reproduit les défauts corrigés |
| Scénario de bout en bout `scripts/scenario-synchro.sh` (outil `lgs`, KeePassXC, banc Apache) | 25 vérifications réussies sur 25, dont COPY, MOVE et MKCOL par HTTPS et la suspension après un refus d'identifiants |
| `cargo fmt --check`, `cargo clippy -D warnings` | Aucune remarque |
| `cargo deny check` : vulnérabilités connues, licences, origines, doublons | Conforme |
| Fichiers de l'intégration continue : syntaxe, actions épinglées par empreinte | Conformes ; passages sur GitHub verts, avant et après la revue |

## 2. Mesures

| Mesure | Valeur |
|---|---|
| Ouverture d'un coffre (Argon2id 32 Mio, 10 itérations), serveur 2 vCPU | 135 à 150 ms |
| Ouverture puis enregistrement vérifié | environ 320 ms |
| Calibrage pour une seconde (même serveur) | 45 itérations |
| 3 000 fichiers altérés : paniques de la bibliothèque seule | 2 à 7 selon les essais, toutes évitées par le contrôle d'en-tête |
| 3 000 fichiers altérés : ouvertures par le noyau | 0 (3 000 erreurs ordinaires) |

## 3. Recette par Hermann

| N° | Essai | Attendu |
|---|---|---|
| R1 | Sur le PC Windows : installer Rust (rustup), récupérer le dépôt, lancer `cargo test --workspace` | Tous les tests réussis. Ceux de KeePassXC et du serveur sont ignorés si leurs outils sont absents |
| R2 | `lgs new` (avec `--keyfile`), `lgs add`, puis ouvrir le coffre dans KeePassXC pour Windows. Modifier une entrée dans KeePassXC, puis `lgs show` | Entrées lisibles des deux côtés ; la modification apparaît |
| R3 | Copier ce coffre et le fichier clé sur le téléphone Android, l'ouvrir avec KeePassDX, ajouter une entrée, recopier le fichier, puis `lgs merge` | L'entrée ajoutée sur Android est fusionnée |
| R4 | Facultatif, si un iPhone est disponible : même essai avec KeePassium | Coffre lisible |
| R5 | Une fois le serveur « coffre » déployé et un compte de recette créé : lancer `scripts/scenario-synchro.sh` (Linux ou WSL), avec `LGS_TEST_WEBDAV_URL=https://coffre.ligrivs.com/dav/<compte>/`. Saisir le mot de passe au clavier : `read -rs LGS_TEST_WEBDAV_PASSWORD; export LGS_TEST_WEBDAV_PASSWORD`. Contre le serveur déployé, le scénario ne provoque aucun refus d'identifiants : CrowdSec bannit l'adresse 4 heures après cinq échecs en rafale. Éviter aussi de relancer le scénario après une erreur de saisie du mot de passe | 22 vérifications réussies (20 sans keepassxc-cli), dont COPY et MOVE par HTTPS |
| R6 | Sur GitHub, dans la demande de fusion n° 1 : consulter l'onglet *Checks* | Les quatre travaux de l'intégration continue sont verts : vérifications (Linux), Windows, interopérabilité, dépendances |

Critère de sortie du jalon 0 : R1, R2, R3, R5 et R6 réussis.

## 4. Résultats de la recette par Hermann (11 novembre 2026)

| N° | Résultat | Constats |
|---|---|---|
| R1 | En attente du bilan | Rust est installé et le dépôt compile sous Windows : l'outil `lgs`, installé avec `cargo install`, a servi pour R2 et R3. Reste à relever le total des tests (80 réussis attendus). |
| R2 | Réussi | Le coffre créé par `lgs` s'ouvre dans KeePassXC pour Windows, avec le fichier clé. La modification faite dans KeePassXC est relue par `lgs` (`Versions antérieures : 1`). En sens inverse, `lgs` ouvre un coffre et un fichier clé (format XML 2.0) créés par KeePassXC. À l'écriture, il garde les réglages de KeePassXC (64 Mio, 60 itérations, 4 voies) et passe le coffre en Argon2id et KDBX 4.1 |
| R3 | Réussi | Le coffre s'ouvre avec KeePassDX sur Android, fichier clé compris. L'entrée ajoutée sur le téléphone est fusionnée par `lgs merge` (`1 ajout(s)`), et l'entrée Banque est conservée |
| R4 | Non fait | Facultatif : pas d'iPhone disponible |
| R5 | Réussi | 22 vérifications sur 22 contre le serveur en service (`https://coffre.ligrivs.com/dav/recette-j0/`), depuis WSL (Ubuntu 24.04). Elles couvrent la convergence de deux terminaux, la lecture par KeePassXC du coffre du serveur, COPY et MOVE en 201 par HTTPS, MKCOL refusé (403) et les refus de `lgs`. Aucun échec d'authentification n'a été provoqué |
| R6 | Réussi | Intégration continue verte, avant et après la revue |

Points relevés pendant la recette, à reprendre au jalon 1 :
- Un fichier introuvable donne `erreur d'entrée-sortie : Le fichier spécifié est introuvable. (os error 2)`, sans dire s'il s'agit du coffre ou du fichier clé. Le message doit nommer le fichier.
- `lgs list` n'affiche rien pour un coffre sans entrée. Un message explicite éviterait le doute.
- La fusion d'une copie modifiée par KeePassDX ou KeePassXC compte aussi `1 mise(s) à jour` : ces applications modifient les dates du groupe racine. C'est sans conséquence.
