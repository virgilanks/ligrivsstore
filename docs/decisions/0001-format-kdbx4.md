# 0001 — Format des coffres : KDBX 4, norme ouverte

- Date : 11 novembre 2026
- Statut : adoptée (décision d'Hermann)

## Contexte

Le gestionnaire doit être le plus sûr possible, fonctionner hors ligne sur chaque terminal et pouvoir être vendu. Deux voies : un format propre ou le format ouvert de KeePass (KDBX), documenté et lu par de nombreuses applications.

## Décision

Les coffres sont des fichiers KDBX 4. Le noyau les écrit toujours en KDBX 4.1.

## Conséquences

- L'utilisateur peut ouvrir son coffre avec KeePassXC, KeePassDX ou KeePassium : il n'est jamais captif, ce qui est un argument de vente.
- Le format est éprouvé et analysé publiquement ; le chiffrement n'est pas réinventé.
- Ces applications servent de référence aux tests d'interopérabilité (KeePassXC automatiquement, KeePassDX et KeePassium à la main).
- Un coffre ouvert en KDBX 3.1 ou 4.0 est converti en 4.1 à la première écriture. Les applications récentes lisent ce format (KeePassXC 2.7, testé).
- Contrainte héritée : les dates sont à la seconde (voir 0007).
