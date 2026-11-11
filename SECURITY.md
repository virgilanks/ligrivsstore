# Sécurité

## Signaler une vulnérabilité

Ne décrivez jamais une vulnérabilité dans un ticket ou une demande de fusion. Signalez-la directement au responsable du projet. Tout signalement reçoit une réponse sous 7 jours. Une adresse de contact dédiée sera publiée avec la première version vendue.

## Ce que le projet protège

- Les identifiants, mots de passe, adresses et notes enregistrés dans les coffres.
- La disponibilité des coffres : aucun fichier, même hostile, ne doit arrêter l'application, et aucune synchronisation ne doit perdre une modification.

## Modèle de menace (résumé)

| Menace | Réponse |
|---|---|
| Vol du fichier du coffre (terminal, serveur, sauvegarde) | Chiffrement KDBX 4.1 ; Argon2id 32 à 64 Mio ; phrase de passe et fichier clé |
| Serveur, Cloudflare ou relais compromis | Le serveur ne voit que des fichiers chiffrés et authentifiés ; une altération est détectée ; un fichier hostile est refusé avant tout calcul coûteux (décision 0006) |
| Terminaison du HTTPS chez Cloudflare | Cloudflare voit le mot de passe WebDAV (authentification Basic) et les fichiers. Ceux-ci restent chiffrés par KDBX. Le mot de passe WebDAV ne donne accès qu'à ces fichiers ; il est distinct de la phrase de passe du coffre et renouvelable en une commande. Risque accepté (décision 0008) |
| Blocage d'un foyer par CrowdSec (mot de passe changé, application qui réessaie) | Suspension de la synchronisation dès le premier refus, jusqu'à une nouvelle saisie (décision 0008) |
| Écrasement par un autre terminal | Envoi conditionnel (If-Match) et fusion (décision 0003) |
| Coupure pendant un enregistrement | Écriture atomique, relecture de contrôle, dix sauvegardes locales |
| Interception réseau | HTTPS obligatoire ; aucun identifiant dans les adresses ; aucune redirection suivie |
| Fuite par les journaux ou la mémoire | Secrets masqués à l'affichage ; effacement des tampons sensibles (`zeroize`) |
| Dépendance compromise ou vulnérable | Versions épinglées ; `cargo-deny` (vulnérabilités connues, licences, origines) à chaque compilation ; actions GitHub épinglées par empreinte |

Hors périmètre au jalon 0 : terminal déjà compromis (enregistreur de frappe, accès administrateur), remplissage dans les navigateurs (jalon 1), déverrouillage biométrique (jalon 2).

## Règles du dépôt

- Aucun secret dans le dépôt : ni mot de passe, ni clé, ni jeton, ni coffre réel. Le fichier `.gitignore` écarte les fichiers `.kdbx`, `.keyx` et `.env`.
- Les tests n'utilisent que des phrases de test générées ou explicitement non secrètes.
- L'outil `lgs` lit les secrets dans des variables d'environnement, jamais sur la ligne de commande.
- Toute modification du noyau passe par une demande de fusion, l'intégration continue et une relecture.
- Un audit de sécurité externe est prévu avant toute vente.
