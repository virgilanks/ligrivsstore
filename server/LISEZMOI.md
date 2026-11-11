# Serveur « coffre » — copie de référence

Le dossier `coffre/` contient les fichiers du service « coffre » **revus par la conversation « infra » le 11 novembre 2026** : archive `coffre-revu-20261111.zip`, reprise sans modification. On y trouve la fiche de déploiement (`service.yaml`), `compose.yaml`, la configuration Apache et les scripts d'exploitation.

- **Version en service** : celle de `/opt/sites/coffre` sur coffre01 (VM 131, 10.10.30.11, port 8080, httpd 2.4.70).
- **Toute évolution** de ces fichiers repasse par une revue de la conversation « infra », avant d'être reportée ici.
- **Banc d'essai** : `scripts/banc-webdav.sh` démarre Apache avec exactement ces directives, chemins adaptés, derrière un relais HTTPS qui joue le rôle de Cloudflare et de Caddy. Ce relais est indispensable : le défaut de MOVE et COPY corrigé par la revue (502 « Destination URI refers to different scheme or port ») n'apparaît que lorsque le client parle en HTTPS.
- **Tests du serveur** : `scripts/tests-serveur.sh` (63 tests par le relais), lancés aussi par l'intégration continue.

## Ce que la revue a corrigé

| Sujet | Correction |
|---|---|
| MOVE et COPY par HTTPS | `ServerName https://${PUBLIC_HOSTNAME}:443` (httpd.conf) |
| Renouvellement d'un mot de passe | Dossier `./auth` monté en entier (compose.yaml) |
| Sous-dossiers, non suivis par l'historique | `Require not method MKCOL` dans chaque bloc d'utilisateur (utilisateurs.sh) |
| Accès depuis le VLAN 30 | Filtre local sur coffre01 ; port publié en IPv4 seulement |
| Version d'Apache | `httpd:2.4.70-trixie` |

Vérification sur le banc du dépôt, par le relais HTTPS :
- configuration revue : 63 tests réussis sur 63 ;
- configuration d'avant la revue : 9 échecs, dont MOVE et COPY (502) et MKCOL accepté.

Le banc reproduit donc les défauts et valide leur correction.

## Règles pour les applications

- **Emplacement du coffre** : à la racine du dossier du compte, `/dav/<compte>/<coffre>.kdbx` (pas de sous-dossier).
- **Nom du fichier** : jamais un nom de fichier temporaire (`.tmp`, `~`, `.lock`, nom commençant par un point). Ces fichiers ne sont pas historisés.
- **Taille** : 50 Mo au plus par fichier.
- **Refus d'identifiants** : CrowdSec ne compte que les échecs où des identifiants ont été envoyés. Cinq échecs en rafale bannissent l'adresse pendant 4 heures. Les applications envoient donc leurs identifiants dès la première requête et ne réessaient jamais seules après un refus.

Le noyau `ligrivsstore-core` applique ces règles (voir `docs/decisions/0008-regles-du-serveur-revu.md`).
