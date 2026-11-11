# 0005 — Premier jalon sans iPhone ni iPad

- Date : 11 novembre 2026
- Statut : adoptée (décision d'Hermann : pas de Mac disponible pour le moment)

## Contexte

Compiler, signer et publier une application iOS demande un Mac avec Xcode. Hermann n'en dispose pas pour l'instant.

## Décision

- Le premier jalon couvre Windows avec l'extension Chrome et Edge, puis Android.
- L'iPhone et l'iPad, puis le Mac avec Safari, passent après la bêta, dès qu'un Mac sera disponible (achat, location en ligne ou compilation sur les machines macOS de GitHub Actions).
- L'architecture reste prête pour iOS : noyau en Rust (liaisons Swift par UniFFI), dérivation limitée à 64 Mio (0004), plafonds `OpenLimits::ios_autofill()`.

## Conséquences

- Le plan jusqu'à la bêta passe de cinq à quatre jalons, soit environ trois mois au lieu de quatre à cinq.
- Les utilisateurs d'iPhone peuvent, en attendant, ouvrir leur coffre avec KeePassium (format ouvert, 0001) et la synchronisation WebDAV du serveur « coffre ».
