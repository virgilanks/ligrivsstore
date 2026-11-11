# 0004 — Dérivation de clé : Argon2id, 32 à 64 Mio

- Date : 11 novembre 2026
- Statut : adoptée

## Contexte

La dérivation (Argon2) rend chaque essai de phrase de passe coûteux pour un attaquant qui aurait volé le fichier. Plus de mémoire et d'itérations, c'est plus de sécurité, mais aussi une ouverture plus lente. L'extension de remplissage automatique d'iOS ne dispose que d'environ 120 Mo de mémoire. Au-delà d'environ 64 Mio de dérivation, l'ouverture y échoue (constat publié par KeePassium et Bitwarden).

## Décision

- À la création : Argon2id 1.3, 32 Mio, 2 voies, itérations calibrées pour environ une seconde sur le terminal le plus lent (10 par défaut).
- À chaque enregistrement, les paramètres sont normalisés : passage en Argon2id, mémoire ramenée entre 32 et 64 Mio, au moins 4 itérations, 1 à 8 voies. Un coffre en AES-KDF (ancien mécanisme, sans résistance mémoire) passe aux paramètres par défaut.
- Les réglages par défaut de la bibliothèque (Argon2d, 1 Mio) ne sont jamais écrits (test dédié).

## Conséquences

- Un coffre créé ou modifié par ligrivsstore s'ouvrira dans l'extension AutoFill de la future application iPhone : l'architecture reste prête, même si l'iPhone est différé (0005).
- Un coffre de KeePassXC à plus de 64 Mio passe à 64 Mio à la première écriture : c'est le prix de la compatibilité iOS.
- Mesures sur le serveur de test : environ 140 ms pour 10 itérations. Un téléphone d'entrée de gamme est trois à cinq fois plus lent. Le calibrage se fera sur les appareils réels au jalon 2.
