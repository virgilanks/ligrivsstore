# 0010 — Application Windows : structure, cloisonnement de l'interface, licences

- Date : 11 novembre 2026
- Statut : adoptée (semaine 1 du jalon 1)

## Contexte

La note de conception n° 3 (v1.1) a fixé l'application Windows : Tauri 2 et Svelte 5, le coffre et sa clé dans le processus Rust, l'interface dans WebView2. La semaine 1 en livre le squelette : création, ouverture et verrouillage du coffre, liste et fiche des entrées, générateur, installateur produit par l'intégration continue.

Trois questions se sont posées en la réalisant : où placer le code, comment cloisonner l'interface, et que faire des quelques dépendances de Tauri sous licence MPL-2.0.

## Décision

### Structure

- **`crates/app` (`ligrivsstore-app`)** porte toute la logique de l'application : session (coffre ouvert ou verrouillé, entrées, enregistrement), réglages, messages échangés avec l'interface, codes d'erreur, robustesse des phrases de passe. Ce paquet ne dépend pas de Tauri : il est testé avec le reste du dépôt, sous Linux et sous Windows, sans fenêtre.
- **`apps/windows`** suit la disposition standard de Tauri : l'interface Svelte dans `src/`, la coquille Rust dans `src-tauri/`. La coquille ne fait que relayer chaque commande vers la session, dans une tâche à part : la dérivation Argon2id ne fige jamais la fenêtre.
- La coquille forme un **espace de travail Cargo à part**, exclu de celui du dépôt : sa compilation exige l'interface construite et les bibliothèques de WebView. Les vérifications du noyau restent ainsi rapides et indépendantes de Node.js. Elle a son propre `Cargo.lock` et son propre suivi Dependabot.
- Versions exactes, vérifiées sur crates.io et npm le 11 novembre 2026 : Tauri 2.12.5 (tauri-build 2.7.4), extensions dialog 2.8.4 et single-instance 2.5.5 ; Svelte 5.57.3, Vite 8.3.8, svelte-check 4.7.8 ; TypeScript 6.0.3, car svelte-check ne prend pas encore en charge TypeScript 7 ; zxcvbn 3.1.1 (licence MIT) pour la robustesse des phrases de passe.

### Cloisonnement de l'interface

L'interface est traitée comme du code exposé. Quatre barrières se superposent :

| Barrière | Disposition |
|---|---|
| Liste des commandes | `build.rs` déclare les 14 commandes de l'application. Toute autre commande n'existe pas pour l'interface |
| Permissions de Tauri | `capabilities/principale.json` n'accorde à la fenêtre principale, et pour le contenu local seulement, que ces 14 commandes et les boîtes de dialogue d'ouverture et d'enregistrement de fichiers. Aucun événement, aucune gestion de fenêtre, aucun accès aux fichiers par l'interface |
| Motif d'isolation | Chaque message de l'interface passe par un cadre isolé qui ne transmet que la même liste, puis est chiffré vers le cœur Rust. Une commande non prévue reçoit une erreur |
| Politique de contenu (CSP) | `default-src`, `script-src` et `style-src` limités à l'application, sans `unsafe-inline` ; `object-src`, `base-uri` et `form-action` interdits ; aucune ressource distante ; prototypes JavaScript gelés |

Les secrets restent dans le processus Rust : l'interface reçoit des listes et des fiches sans mot de passe. Un mot de passe ne lui parvient que sur le bouton « Afficher ». La phrase de passe n'est jamais enregistrée ; les réglages ne retiennent que l'emplacement du dernier coffre et celui de son fichier clé.

Un essai de l'application compilée, sous Linux (WebKitGTK), dans un écran virtuel, a vérifié ces barrières en fonctionnement. Il a aussi révélé un défaut, corrigé : Tauri masque son cadre d'isolation par une feuille de style ajoutée en ligne, que notre politique de contenu bloque à juste titre ; le cadre apparaissait alors en bas de la page. Une règle de la feuille de style de l'application le masque désormais. Cet essai sera automatisé avec les essais de bout en bout de la semaine 5 ; d'ici là, il est à refaire à chaque nouvelle version de Tauri.

### Création d'un coffre

- La dérivation Argon2id est calibrée sur le poste pour environ 0,8 seconde à l'ouverture.
- La phrase de passe doit compter au moins 12 caractères et obtenir au moins 3 sur 4 selon zxcvbn ; une jauge l'évalue pendant la saisie.
- Le fichier clé est proposé par défaut. Il est créé dans `%LOCALAPPDATA%\ligrivsstore-cles` :
  - OneDrive ne synchronise pas ce dossier : le fichier clé ne rejoint jamais le coffre sur un serveur ;
  - ce n'est pas le dossier de l'application (`%LOCALAPPDATA%\com.ligrivs.ligrivsstore`), que le désinstallateur de Tauri efface entièrement quand on coche « Supprimer les données de l'application ». Perdre le fichier clé, c'est perdre le coffre.
- L'écran rappelle d'en garder une copie à part.

### Licences

La politique reste : licences permissives seulement, aucune licence à réciprocité forte (GPL, LGPL, AGPL). La MPL-2.0, dont la réciprocité s'arrête aux fichiers du paquet lui-même, est admise pour cinq paquets nommés dans `deny.toml`, et pour eux seuls :

| Paquet | Arrivée | Dans le programme livré |
|---|---|---|
| `option-ext` 0.2.0 | `dirs-sys` → `dirs` → `tauri` | Oui, sans modification |
| `cssparser` 0.37.0, `cssparser-macros` 0.7.1, `dtoa-short` 0.3.5, `selectors` 0.38.0 | `tauri-utils` → `tauri-codegen` → `tauri-macros` (macro procédurale) | Non : outils de compilation |

La MPL-2.0 n'impose rien à notre propre code. Pour `option-ext`, livré sans modification, elle demande d'indiquer où trouver son code source : <https://crates.io/crates/option-ext>.

Le contrôle `cargo-deny` de l'application porte sur les paquets compilés pour Windows (`--target x86_64-pc-windows-msvc`). Les paquets propres à Linux (WebKitGTK) n'entrent pas dans le programme livré.

## Conséquences

- L'intégration continue construit l'interface, vérifie la coquille (format, clippy) et produit l'installateur NSIS, installé pour l'utilisateur courant, sans droits d'administrateur. Il est conservé 30 jours parmi les fichiers de l'exécution.
- L'installateur n'est pas signé au jalon 1 : Windows SmartScreen avertit à l'installation (décision D3 : signature avant la bêta).
- Avant la bêta, l'installateur embarquera un fichier de mentions des logiciels tiers, généré à partir des paquets Rust et npm livrés.
- Restent pour les semaines suivantes du jalon 1 : phrases de passe générées (liste de l'EFF, décision D8), synchronisation, verrouillage automatique, presse-papiers protégé, puis relais, extension et remplissage.
