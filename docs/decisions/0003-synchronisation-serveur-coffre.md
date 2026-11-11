# 0003 — Synchronisation par le serveur « coffre » (WebDAV), fusion sur le terminal

- Date : 11 novembre 2026
- Statut : adoptée (décision d'Hermann)

## Contexte

Le serveur « coffre » (Apache, WebDAV, un dossier par utilisateur, historique de 30 jours) est déjà conçu pour l'infrastructure Zanzibar. Le TLS se termine chez Cloudflare : le serveur doit rester aveugle et ne recevoir que des fichiers chiffrés.

## Décision

- Aucun développement serveur : toute l'intelligence est dans le noyau.
- Envoi conditionnel : `If-Match` avec l'étiquette (ETag) de la version fusionnée, ou `If-None-Match: *` pour une création. Un refus (412) déclenche un nouveau téléchargement, une fusion et un nouvel essai (5 au plus).
- Les étiquettes faibles (`W/…`), qu'Apache renvoie pendant la seconde qui suit une écriture, ne sont jamais utilisées pour un envoi : la boucle attend 1,1 s puis relit (3 fois au plus).
- Après un envoi, l'étiquette n'est pas conservée. La synchronisation suivante télécharge le coffre et reconnaît sa propre version par son empreinte SHA-256, sans fusion.
- Un coffre distant illisible, chiffré avec une autre clé ou d'une autre identité (groupe racine différent) arrête la synchronisation, sans rien envoyer.
- `https://` est obligatoire ; `http://` n'est admis que vers la machine locale (bancs de test).

## Conséquences

- Vérifié sur le banc Apache avec la configuration livrée : création conditionnelle (412 au second créateur), conflit réel (412) puis reprise, attente des étiquettes faibles, cloisonnement entre comptes, lecture du résultat par KeePassXC.
- Coût : jusqu'à deux dérivations de clé par envoi (sérialisation, relecture de contrôle) et une après chaque envoi d'un autre terminal (ouverture du coffre distant).
- Pour la version vendue dans les stores, d'autres transports (iCloud Drive, Google Drive) pourront implémenter le même trait `Transport`.
- Complétée par la décision 0008 (revue infra du 11 novembre 2026) : emplacement à la racine du dossier du compte, noms de fichiers temporaires refusés, 50 Mo au plus, suspension après un refus d'identifiants (CrowdSec), banc derrière un relais HTTPS.
