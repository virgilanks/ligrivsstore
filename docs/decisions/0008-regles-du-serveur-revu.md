# 0008 — Règles du serveur « coffre » revu, appliquées par le noyau

- Date : 11 novembre 2026
- Statut : adoptée (revue infra du 11 novembre 2026)

## Contexte

La conversation « infra » a revu le serveur « coffre » avant son déploiement :
- coffre01, VM 131, 10.10.30.11 ;
- port 8080 ;
- httpd 2.4.70.

Les corrections apportées par cette revue imposent des règles aux applications :

- l'historique ne suit que la racine de chaque dossier, et le serveur refuse désormais la création de sous-dossiers (MKCOL) ;
- les fichiers au nom de fichier temporaire (`.tmp`, `~`, `.lock`, nom commençant par un point) ne sont pas historisés ;
- un envoi est limité à 50 Mo par fichier ;
- CrowdSec ne compte que les échecs où des identifiants ont été envoyés, et en bannit l'adresse pendant 4 heures après cinq en rafale.

Par ailleurs, Cloudflare termine le chiffrement HTTPS. Il voit donc passer le mot de passe WebDAV, envoyé à chaque requête par l'authentification Basic, ainsi que les fichiers. Ces fichiers restent chiffrés par KDBX sur les terminaux.

## Décision

Le noyau applique ces règles lui-même, avant toute requête :

- **Emplacement** : une adresse en `/dav/` doit être de la forme `/dav/<compte>/<coffre>.kdbx`, avec `<compte>` égal au compte WebDAV. Sinon : refus local, donc aucun 401 compté par CrowdSec.
- **Nom** : extension `.kdbx` obligatoire ; noms de fichiers temporaires refusés.
- **Taille** : envoi refusé localement au-delà de 50 Mo (`MAX_UPLOAD_BYTES`).
- **Identifiants** : envoyés à chaque requête ; après un refus (401), la synchronisation est suspendue. L'état est enregistré dans `coffre.kdbx.synchro.json` et survit à un redémarrage. Il est levé par `LocalVault::accept_new_credentials`, ou par `lgs sync --new-credentials`, après une nouvelle saisie.
- **Banc d'essai** : Apache derrière un relais HTTPS (autorité de certification locale). Le noyau accepte une autorité explicite (`WebDavTransport::with_root_ca`, `lgs --ca-file`) ; par défaut, seules les autorités publiques sont reconnues.

## Conséquences

- Une application qui réessaierait seule après un changement de mot de passe ne peut plus faire bannir le foyer entier : tous les terminaux partagent la même adresse publique.
- Les tests contre le serveur déployé (`webdav.rs`, scénario de recette) ne provoquent aucun refus volontaire. Ces cas ne sont joués que sur le banc local.
- Le risque lié à la terminaison TLS chez Cloudflare est accepté. Le mot de passe WebDAV ne protège que l'accès à des fichiers chiffrés et authentifiés : il est distinct de la phrase de passe du coffre et renouvelable en une commande. Le dossier de conception du serveur (v1.2) le détaille.
- Vérifié par les tests :
  - unitaires : noms, emplacements, taille, autorité ;
  - suspension, avec le serveur simulé et sur le banc ;
  - scénario de bout en bout : COPY, MOVE et MKCOL par HTTPS ;
  - tests du serveur : 63 réussis sur 63 par le relais.
