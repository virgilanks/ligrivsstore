# coffre — synchronisation des coffres (format KDBX) de l'application KEEPASS

Livrables du sous-projet KEEPASS, à joindre dans la conversation « infra » avec le dossier de conception (Word). Aucun secret dans ce dossier.

| Fichier | Rôle |
|---|---|
| `service.yaml` | Fiche de déploiement (modèle 1) |
| `compose.yaml` | Deux conteneurs : `webdav` (httpd:2.4.70-trixie) et `versions` (busybox:1.37.0) |
| `.env.example` | Paramètres sans secret : `PUBLIC_HOSTNAME`, `EDGE01_IP`, `PORT_HTTP`, historique |
| `config/httpd.conf` | Apache durci : WebDAV, cloisonnement par utilisateur, `/healthz` |
| `config/healthz.txt` | Réponse « ok » du contrôle de santé |
| `scripts/utilisateurs.sh` | Comptes WebDAV : `preparer`, `ajouter`, `renouveler`, `supprimer`, `lister` |
| `scripts/historique.sh` | Historique des coffres (exécuté par le conteneur `versions`) |

## Déploiement sur coffre01 (après la revue)

1. Copier ce dossier dans `/opt/sites/coffre`.
2. `cp .env.example .env && chmod 600 .env`, puis renseigner `EDGE01_IP` et `PORT_HTTP`.
3. `./scripts/utilisateurs.sh preparer` : crée `auth/` et `data/` avec les bons propriétaires (www-data, 33:33). **À faire avant le premier démarrage** : sinon Docker crée un dossier à la place du fichier `auth/htpasswd`.
4. `docker compose pull && docker compose up -d`, puis `docker compose ps` (état *healthy*).
5. `curl -s http://127.0.0.1:$PORT_HTTP/healthz` doit renvoyer `ok`.
6. Comptes : `./scripts/utilisateurs.sh ajouter <nom>`. Le mot de passe WebDAV s'affiche une seule fois ; il se saisit directement dans les applications de l'utilisateur.

## Points pour Caddy, Cloudflare et CrowdSec

- Relais vers `coffre01:PORT_HTTP` en transmettant `X-Forwarded-For` (adresse réelle du client). Aucune mise en cache.
- AppSec : tester `/dav/` et `/versions/` (méthodes WebDAV, corps XML, fichiers binaires jusqu'à 50 Mo) et prévoir des exemptions ciblées si besoin.
- Cloudflare : ni « Bot Fight Mode » ni défi de navigateur sur ce nom, car les clients WebDAV ne sont pas des navigateurs.
- CrowdSec : bannir les rafales de réponses 401 sur `/dav/`.

## Ce qui a été vérifié en conception

59 tests réussis sur un banc Apache 2.4 (mêmes directives, autres chemins) : santé et en-têtes, authentification, cloisonnement (y compris MOVE et COPY vers le dossier d'un autre), méthodes WebDAV, verrous, limite de 50 Mo, historique (copie, non-duplication, purge à 30 jours en gardant la dernière copie), lecture seule de l'historique, adresse réelle dans les journaux, absence de mot de passe dans les journaux, script de comptes (création, doublon, nom invalide, renouvellement, suppression). `docker compose config` valide le fichier compose. Preuve de concept du 11 novembre 2026 (14 tests réussis) : envoi conditionnel `If-Match` (204 ou 412), ETag faible pendant la seconde qui suit une écriture, fusion sans perte entre deux terminaux.

## Revue infra du 11 novembre 2026

Corrections intégrées avant le déploiement, vérifiées sur banc (21 tests, plus MKCOL) :

| Sujet | Constat | Correction |
|---|---|---|
| MOVE et COPY par HTTPS | Apache renvoie 502 « Destination URI refers to different scheme or port » : l'en-tête Destination est en https, Apache écoute en http | `ServerName https://${PUBLIC_HOSTNAME}:443` (httpd.conf) ; l'en-tête Location des 201 passe aussi en https |
| Renouvellement d'un mot de passe | utilisateurs.sh remplace `auth/htpasswd` par un nouveau fichier ; un montage du seul fichier montre toujours l'ancien au conteneur, jusqu'à son redémarrage | Montage du dossier `./auth` entier (compose.yaml) |
| Historique | `historique.sh` ne suit que la racine de chaque dossier, mais MKCOL permettait des sous-dossiers | Blocs d'utilisateur : `Require not method MKCOL` (utilisateurs.sh) |
| Accès depuis le VLAN 30 | apps01 joint coffre01 sans passer par OPNsense | Filtre local sur coffre01 (edge01 et mon01 seulement) ; port publié en IPv4 seulement (compose.yaml) |
| Version d'Apache | httpd 2.4.70 publiée dans le catalogue officiel le 10 novembre | `httpd:2.4.70-trixie` |

Côté infrastructure : Caddy transmet l'adresse réelle du visiteur seule dans `X-Forwarded-For` (sinon Apache journalise 127.0.0.1) ; CrowdSec ignore les défis d'authentification sans identifiants (401 sans en-tête Authorization) et compte les échecs réels.
