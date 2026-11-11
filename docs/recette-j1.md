# Recette du jalon 1 — application Windows et extension

Le jalon 1 dure cinq semaines (note de conception n° 3, v1.1). Chaque semaine se conclut par une demande de fusion, l'intégration continue au vert et un livrable vérifiable. La recette complète, R1 à R11, a lieu en semaine 5.

## Semaine 1 — squelette de l'application

Livrable vérifiable : **un installateur qui crée, ouvre et modifie un coffre.**

### 1. Essais automatiques (11 novembre 2026)

| Essai | Résultat |
|---|---|
| Tests du dépôt (`cargo test --workspace`, Linux, Rust 1.97.0), dont 16 nouveaux pour `ligrivsstore-app` : création refusée si la phrase est faible ou le coffre existe, fichier clé créé puis retiré si la création échoue, ouverture avec ou sans fichier clé, verrouillage, recherche, modification sans changement, mot de passe conservé, réglages, erreurs, robustesse | 115 réussis, 0 échec |
| Interface : `svelte-check` (TypeScript strict) | 0 erreur, 0 remarque |
| Coquille Tauri : `cargo fmt`, `cargo clippy -D warnings` | Aucune remarque |
| `cargo deny` : dépôt, puis application Windows (paquets de Windows) | Conformes, avec les cinq exceptions MPL-2.0 de la décision 0010 |
| `npm audit` | Aucune vulnérabilité dans les paquets livrés ; 2 de faible gravité dans les outils de construction (deepmerge, par vite-plugin-svelte) |
| Intégration continue sur GitHub (Rust 1.99.1) : Linux, Windows avec KeePassXC 2.8.0, banc Apache, cargo-deny, application Windows | Verte : 115 tests sous Linux, 116 sous Windows (1 ignoré) ; installateur `ligrivsstore_0.1.0_x64-setup.exe` (2,55 Mio) produit en 12 minutes |

### 2. Essai de l'application compilée

L'application, compilée sous Linux (WebKitGTK 2.52), a été pilotée dans un écran virtuel, au clavier et à la souris, comme le ferait un utilisateur. Cet essai vérifie en fonctionnement la politique de contenu, le motif d'isolation et les permissions de Tauri.

| Étape | Résultat |
|---|---|
| Démarrage : interface, styles et scripts chargés malgré la politique de contenu stricte | Réussi |
| Création : jauge de robustesse (« Trop courte », puis « excellente »), fichier clé créé, coffre ouvert | Réussi |
| Entrée : saisie, mot de passe généré (20 caractères, environ 130 bits), notes, enregistrement | Réussi |
| Afficher et masquer le mot de passe ; modifier (une version antérieure) ; rechercher ; supprimer après confirmation | Réussi |
| Verrouiller ; mauvaise phrase de passe refusée avec un message clair ; déverrouiller | Réussi |
| Relance : dernier coffre et fichier clé proposés ; « Changer de coffre » les oublie | Réussi |
| Coffre créé par l'application ouvert par KeePassXC 2.7.6 et par l'outil `lgs` (KDBX 4.1, Argon2id) | Réussi |

Défauts trouvés pendant l'essai, corrigés :

- le cadre d'isolation de Tauri apparaissait en bas de la page : sa feuille de style en ligne est bloquée par notre politique de contenu. La feuille de style de l'application le masque désormais (décision 0010) ;
- à la deuxième « Nouvelle entrée », le titre ne recevait pas le focus. Chaque clic ouvre maintenant un formulaire vide, titre sélectionné ;
- un long chemin de coffre repoussait les boutons de la barre d'outils. Il est maintenant tronqué ; le chemin complet s'affiche au survol.

Défaut trouvé en relisant le désinstallateur de Tauri, corrigé : la case « Supprimer les données de l'application » efface le dossier de l'application, où le fichier clé était d'abord proposé. Il est maintenant proposé dans `%LOCALAPPDATA%\ligrivsstore-cles`, que la désinstallation ne touche pas.

### 3. Recette par Hermann

Sur votre PC Windows, sans PowerShell. Utilisez une phrase de passe neuve, propre à ce coffre d'essai. Comme toujours, ne la communiquez à personne, pas même dans une conversation avec Claude.

| N° | Étape | Attendu |
|---|---|---|
| S1-1 | Sur la page de la demande de fusion n° 3, ouvrir l'onglet « Checks », puis l'exécution « Intégration continue ». Dans « Summary », section « Artifacts », télécharger `ligrivsstore-installateur-windows`, puis extraire le fichier .zip | Un fichier `ligrivsstore_0.1.0_x64-setup.exe` |
| S1-2 | Lancer ce fichier. SmartScreen avertit, car l'installateur n'est pas encore signé : « Informations complémentaires », puis « Exécuter quand même » | Installation sans demande de droits d'administrateur ; ligrivsstore dans le menu Démarrer |
| S1-3 | Lancer ligrivsstore, puis « Créer un coffre ». Garder les emplacements proposés et l'option « Créer un nouveau fichier clé » | Jauge « bonne » ou « excellente » exigée ; coffre ouvert après environ une seconde |
| S1-4 | Ajouter trois entrées, dont une avec un mot de passe généré. Afficher puis masquer un mot de passe. Modifier l'identifiant d'une entrée. En supprimer une autre | Liste à jour ; « Versions antérieures : 1 » sur l'entrée modifiée |
| S1-5 | Verrouiller. Essayer une mauvaise phrase de passe, puis la bonne | « Phrase de passe ou fichier clé incorrect. », puis coffre ouvert |
| S1-6 | Fermer l'application, puis la relancer | Écran de déverrouillage, coffre et fichier clé déjà renseignés |
| S1-7 | Pendant qu'elle est ouverte, lancer ligrivsstore une deuxième fois | Toujours une seule fenêtre, ramenée au premier plan |
| S1-8 | Fermer l'application. Ouvrir `Documents\ligrivsstore\coffre.kdbx` dans KeePassXC, avec la phrase de passe et le fichier clé `%LOCALAPPDATA%\ligrivsstore-cles\coffre.keyx` | Les entrées apparaissent, avec leur historique |
| S1-9 | Copier ce fichier clé sur une clé USB | Copie de secours, rangée à part |
| S1-10 | Désinstaller (Paramètres, Applications), en cochant « Supprimer les données de l'application ». Réinstaller, relancer. « Ouvrir un coffre existant… », choisir le coffre, puis « Choisir… » pour le fichier clé | Écran d'accueil, car les réglages ont été effacés ; le coffre et le fichier clé sont toujours là, et le coffre s'ouvre |

En cas d'écart, une capture d'écran et le numéro de l'étape suffisent.

Ce que la semaine 1 ne contient pas encore : la synchronisation, le verrouillage automatique et le presse-papiers protégé (semaine 2), les phrases de passe générées (semaine 2), l'extension et le remplissage (semaines 3 à 5).

### 4. Résultats de la recette par Hermann (11 novembre 2026)

Les dix étapes, S1-1 à S1-10, sont réussies sur le PC Windows d'Hermann. L'installateur utilisé est celui produit par l'intégration continue de la demande de fusion n° 3. Aucun écart n'a été signalé.

L'étape S1-10 confirme que le coffre et le fichier clé survivent à une désinstallation qui supprime les données de l'application.

**Critère de sortie de la semaine 1 atteint** : l'installateur crée, ouvre et modifie un coffre. La semaine 1 peut être fusionnée.

## Semaine 2 — synchronisation, verrouillage, presse-papiers, sauvegardes

Livrable vérifiable : **deux postes synchronisés par le serveur « coffre »**. S'y ajoutent le verrouillage automatique, le presse-papiers protégé, les sauvegardes, l'installation depuis le serveur et les phrases de passe (décision 0011).

### 1. Essais automatiques (11 novembre 2026)

| Essai | Résultat |
|---|---|
| Tests du dépôt, avec KeePassXC 2.7.6 et le banc Apache derrière le relais HTTPS (Linux, Rust 1.97.0) | 141 réussis, 0 échec, 1 ignoré (générateur des graines du fuzzing) |
| Deux postes (`crates/app/tests/deux_postes.rs`), contre le banc : création et premier envoi, installation depuis le serveur, modifications des deux côtés et convergence, mauvais mot de passe puis suspension, nouvelle saisie | Réussi |
| Pilote (`autopilot`) : verrouillage à l'inactivité, réveil détecté par un saut d'horloge, synchronisation à l'ouverture, 10 s après la dernière modification et toutes les 15 minutes, essais espacés hors ligne, aucun essai après un refus, effacement du presse-papiers | Réussi |
| Session : entrée réservée cachée et refusée aux commandes ordinaires, serveur injoignable (hors ligne), refus d'identifiants (une seule requête, puis plus rien, même après réouverture), pause d'une minute à l'installation après un refus, sauvegardes, copie, réglages, phrases de passe | Réussi |
| Noyau : liste de l'EFF (empreinte SHA-256), phrases de passe, entrées réservées à travers enregistrement et fusion, restauration sans perte, sauvegarde d'un autre coffre refusée | Réussi |
| Sous Windows, dans l'intégration continue : fenêtre cachée qui reçoit verrouillage de session et mise en veille ; presse-papiers protégé (trois formats lus et vérifiés, effacement, copie d'un autre programme respectée) ; clippy sur le code propre à Windows | Réussi (premier passage sur la branche : 126 tests sous Windows) |
| `svelte-check`, `cargo fmt`, `cargo clippy -D warnings` (dépôt et coquille), `cargo deny` (dépôt, application Windows), `npm audit` des paquets livrés | Aucune remarque ; conformes |

### 2. Essai de l'application compilée : deux postes

Deux instances de l'application compilée, chacune avec son propre profil, pilotées au clavier et à la souris dans deux écrans virtuels, contre le banc Apache (accès local en `http://127.0.0.1`).

| Étape | Résultat |
|---|---|
| Poste 1 : création (phrase de passe proposée : six mots de l'EFF), entrée « Banque », réglage de la synchronisation | « À jour » ; coffre créé sur le serveur (GET 404, puis PUT 201) |
| Poste 2 : « Installer le coffre du serveur », avec une copie du fichier clé | Coffre installé, « Banque » présente, entrée réservée cachée |
| Poste 2 : ajout de « Messagerie » | Envoyé 10 s après (GET 304, puis PUT 204) |
| Poste 1 : « Synchroniser maintenant » | « Messagerie » apparaît ; deux entrées |
| Poste 1 : délai de verrouillage réglé à 1 minute, puis aucune action | Écran de déverrouillage : « Coffre verrouillé après 1 minute d'inactivité. » |
| Poste 2 : suppression de « Messagerie », puis restauration de la dernière sauvegarde | « 1 recréée » ; envoyé 10 s après |
| Poste 1 : déverrouillage | Synchronisé à l'ouverture : « Banque » et « Messagerie », sans doublon |
| Les deux fichiers ouverts avec KeePassXC 2.7.6 | Mêmes entrées ; l'entrée réservée porte l'attribut `ligrivsstore-role` |

La copie dans le presse-papiers ne fonctionne que sous Windows : sous Linux, l'application affiche « fonction disponible sous Windows seulement ». Le presse-papiers est vérifié par l'intégration continue sous Windows, et par vous (S2-5).

### 3. Recette par Hermann

Avec le compte de recette `recette-j0` du serveur en service, et un coffre d'essai nommé `recette-j1.kdbx` sur le serveur. Saisissez le mot de passe du serveur sans erreur : le serveur bloque votre adresse pendant 4 heures après cinq refus en rafale. Ne communiquez ni ce mot de passe ni la phrase de passe, pas même dans une conversation avec Claude.

| N° | Étape | Attendu |
|---|---|---|
| S2-1 | Installer l'installateur de la demande de fusion n° 4, par-dessus la version de la semaine 1 | Le coffre de la semaine 1 s'ouvre toujours |
| S2-2 | Onglet « Synchronisation » : adresse `https://coffre.ligrivs.com`, compte `recette-j0`, nom `recette-j1.kdbx`, mot de passe du serveur, puis « Enregistrer » | Pastille « À jour » en quelques secondes |
| S2-3 | Second poste, au choix : un autre PC Windows, avec l'application et « Installer le coffre du serveur… » ; ou l'outil `lgs` dans WSL (commandes ci-dessous) | Les entrées du premier poste y apparaissent |
| S2-4 | Ajouter une entrée sur le second poste et la synchroniser ; dans l'application, « Synchroniser maintenant ». Modifier ensuite une entrée dans l'application, attendre 10 s, synchroniser le second poste | Chaque modification apparaît de l'autre côté ; l'historique garde la version précédente |
| S2-5 | « Copier » un mot de passe, le coller dans le Bloc-notes, puis ouvrir Windows + V ; attendre 30 s et coller de nouveau | Collé une fois ; absent de l'historique ; plus rien à coller après 30 s |
| S2-6 | Réglages : verrouillage après 1 minute ; attendre sans toucher l'application. Puis Windows + L, rouvrir la session. Puis mise en veille et réveil | Trois fois l'écran de déverrouillage, avec le motif : inactivité, session Windows, mise en veille |
| S2-7 | Supprimer une entrée, puis onglet « Sauvegardes » : restaurer la plus récente | L'entrée revient ; après synchronisation, aussi sur le second poste |
| S2-8 | Générateur d'une fiche : « Phrase de passe » ; à la création d'un coffre : « Proposer… » | Mots anglais séparés ; entropie affichée |
| S2-9 | Remettre le verrouillage à 5 minutes | — |

Second poste dans WSL (Ubuntu), depuis le dossier du dépôt, mis à jour par `git pull` après la fusion. Remplacez `<vous>` par votre nom d'utilisateur Windows ; les deux `read` demandent les secrets au clavier, sans les afficher :

```bash
cargo build -p ligrivsstore-cli
cp /mnt/c/Users/<vous>/AppData/Local/ligrivsstore-cles/coffre.keyx ~/recette-j1.keyx
read -rs LGS_PASSWORD && export LGS_PASSWORD                 # phrase de passe du coffre
read -rs LGS_WEBDAV_PASSWORD && export LGS_WEBDAV_PASSWORD   # mot de passe du serveur
URL=https://coffre.ligrivs.com/dav/recette-j0/recette-j1.kdbx
target/debug/lgs clone ~/recette-j1.kdbx --url $URL --user recette-j0 -k ~/recette-j1.keyx
target/debug/lgs list ~/recette-j1.kdbx -k ~/recette-j1.keyx
target/debug/lgs add ~/recette-j1.kdbx --title "Ajout depuis WSL" --username essai --generate 20 -k ~/recette-j1.keyx
target/debug/lgs sync ~/recette-j1.kdbx --url $URL --user recette-j0 -k ~/recette-j1.keyx
```

Si le coffre de la semaine 1 a été créé avec un autre fichier clé, utilisez celui-là. En cas d'écart, une capture d'écran et le numéro de l'étape suffisent.
