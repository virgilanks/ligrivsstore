# 0002 — Noyau partagé en Rust, bibliothèque KDBX épinglée

- Date : 11 novembre 2026
- Statut : adoptée

## Contexte

Les applications Windows, Android puis iPhone doivent partager exactement la même logique de sécurité. Réécrire le chiffrement, le format et la fusion dans trois langages multiplierait les risques d'erreur et le coût d'un audit.

## Décision

- Un noyau unique en Rust (`ligrivsstore-core`), appelé directement par l'application Windows (Tauri) et, par UniFFI, par les applications Android et iPhone. Bitwarden et Proton ont fait le même choix pour leurs clients.
- La lecture et l'écriture KDBX reposent sur la bibliothèque `keepass` (licence MIT), épinglée en version 0.17.0 (`=0.17.0`).
- Le noyau encadre la bibliothèque : contrôle d'en-tête (0006), politique de dérivation (0004), horodatage (0007), écriture atomique, conversion des paniques en erreurs.

## Conséquences

- La licence MIT permet un produit fermé et payant.
- La bibliothèque est jeune : l'écriture KDBX 4.1 y est annoncée comme expérimentale, et la fusion passe par une option non stabilisée (`_merge`). Ces deux risques sont couverts par les tests d'interopérabilité, les tests aléatoires et le contrôle d'en-tête.
- Constats faits au jalon 0 (tests à l'appui) :
  - l'écriture se fait uniquement en KDBX 4.1 ;
  - les réglages de dérivation par défaut sont faibles (Argon2d, 1 Mio) ;
  - certains en-têtes malformés provoquent une panique de la bibliothèque (0,07 à 0,23 % de 3 000 fichiers altérés selon les essais), toutes évitées par le contrôle d'en-tête du noyau ;
  - les octets ajoutés après le dernier bloc sont ignorés, sans effet sur le contenu, qui reste authentifié ;
  - en cas de modification d'une entrée dans la même seconde sur deux terminaux, la fusion garde une version, range l'autre dans l'historique et le signale par un avertissement.
- Toute mise à jour de la bibliothèque passe par une demande de fusion dédiée : relecture du journal des changements, passage complet des tests, dont l'interopérabilité. Les correctifs utiles peuvent être proposés à l'auteur ; à défaut, une bifurcation reste possible (licence MIT).
