# Recette du jalon 0 — fondations

Le jalon 0 livre le noyau, l'outil `lgs`, les tests et l'intégration continue. Livrable vérifiable annoncé : **tests automatiques au vert, y compris le scénario de conflit.**

## 1. Tests automatiques

Résultats du 11 novembre 2026, sur un banc Linux (Rust 1.97.0, KeePassXC 2.7.6, Apache 2.4.58 avec la configuration du serveur « coffre »). La suite complète a été lancée trois fois de suite, sans échec.

| Suite | Ce qui est vérifié | Tests | Résultat |
|---|---|---|---|
| Unitaires (`src/`) | En-tête strict et plafonds, politique de dérivation, calibrage, stockage atomique et sauvegardes, droits des fichiers, étiquettes HTTP, adresses refusées, générateur (familles, longueur, uniformité), historique | 30 | Réussi |
| Coffre (`tests/coffre.rs`) | Aller-retour de tous les champs, KDBX 4.1 et Argon2id écrits, réglages faibles jamais écrits, mauvaise clé, en-têtes hostiles refusés en moins de 200 ms, fichier trop gros, sauvegardes lisibles | 11 | Réussi |
| Fusion (`tests/fusion.rs`) | Ajouts des deux côtés, dernière modification gagnante et historique, suppressions propagées et non ressuscitées, coffres étrangers refusés, modifications rapides et simultanées sans perte | 7 | Réussi |
| Synchronisation simulée (`tests/synchro.rs`) | Création, second terminal, modifications concurrentes, écriture entre téléchargement et envoi (412), reconnaissance de son propre envoi, étiquettes faibles, conflits sans fin, coffre distant d'une autre clé, étranger ou corrompu jamais écrasé, suppressions | 12 | Réussi |
| Interopérabilité (`tests/interop_keepassxc.rs`) | Coffre du noyau lu par KeePassXC (fichier clé exigé), coffre KeePassXC (KDBX 3.1, AES-KDF) modifié par le noyau puis relu, fusion de modifications faites avec KeePassXC | 3 | Réussi |
| Serveur réel (`tests/webdav.rs`) | Convergence de deux terminaux, 412 réel puis reprise, création conditionnelle, mauvais mot de passe, cloisonnement entre comptes, lecture par KeePassXC du coffre du serveur | 5 | Réussi |
| Aléatoires (`tests/robustesse*.rs`) | 512 cas par propriété : octets quelconques, coffres altérés, préfixes, suffixes ; mesure sur 3 000 fichiers altérés | 6 | Réussi |
| **Total** | | **74** | **Réussi** |

Contrôles complémentaires :

| Contrôle | Résultat |
|---|---|
| Scénario de bout en bout `scripts/scenario-synchro.sh` (outil `lgs`, KeePassXC, banc Apache) | 18 vérifications réussies sur 18 |
| `cargo fmt --check`, `cargo clippy -D warnings` | Aucune remarque |
| `cargo deny check` : vulnérabilités connues, licences, origines, doublons | Conforme |
| Fichiers de l'intégration continue : syntaxe, actions épinglées par empreinte | Conformes (validation définitive au premier passage sur GitHub) |

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
| R5 | Une fois le serveur « coffre » déployé et un compte de recette créé : lancer `scripts/scenario-synchro.sh` (Linux ou WSL), avec `LGS_TEST_WEBDAV_URL=https://coffre.ligrivs.com/dav/<compte>/`. Saisir le mot de passe au clavier : `read -rs LGS_TEST_WEBDAV_PASSWORD; export LGS_TEST_WEBDAV_PASSWORD` | 18 vérifications réussies |
| R6 | Après le premier envoi sur GitHub : consulter l'onglet *Actions* | Les trois volets de l'intégration continue sont verts |

Critère de sortie du jalon 0 : R1, R2, R3, R5 et R6 réussis.
