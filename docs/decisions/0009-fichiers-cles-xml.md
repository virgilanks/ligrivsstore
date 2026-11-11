# 0009 — Fichiers clés au format XML 2.0 de KeePass

- Date : 11 novembre 2026
- Statut : adoptée (suite de la recette du jalon 0)

## Contexte

La recette du jalon 0 a utilisé un fichier clé de 64 octets aléatoires. KeePassXC, KeePassDX et le noyau l'acceptent, mais c'est un format « haché », sans contrôle d'intégrité. KeePassXC crée, lui, des fichiers au format XML 2.0 de KeePass : 32 octets aléatoires écrits en hexadécimal, suivis d'une somme de contrôle (les 4 premiers octets de leur empreinte SHA-256).

Jusqu'ici, un fichier clé endommagé donnait « clé incorrecte », ce qui égare l'utilisateur.

## Décision

- Le noyau crée les fichiers clés au format XML 2.0, mis en forme comme KeePassXC (`keyfile::create`, commande `lgs keyfile`).
- Un fichier existant n'est jamais remplacé : perdre un fichier clé, c'est perdre l'accès au coffre.
- À la lecture, la somme de contrôle d'un fichier XML 2.0 est vérifiée, comme dans KeePassXC. Un fichier endommagé est signalé comme tel (`Error::KeyFileCorrupt`).
- Les autres formats restent acceptés selon les règles de KeePass : 32 octets bruts, 64 caractères hexadécimaux, sinon empreinte SHA-256 du fichier.

## Conséquences

- Vérifié dans les deux sens par l'intégration continue, avec keepassxc-cli 2.7.6 sous Linux et 2.8.0 sous Windows :
  - KeePassXC accepte un fichier clé créé par le noyau ;
  - le noyau lit un fichier clé créé par KeePassXC.
- Le noyau donne la même clé pour un fichier XML 2.0 et pour le fichier brut de 32 octets qui contient les mêmes octets, conformément aux règles de KeePass (essai unitaire).
- L'application du jalon 1 proposera de créer le fichier clé et d'en garder une copie à part.
