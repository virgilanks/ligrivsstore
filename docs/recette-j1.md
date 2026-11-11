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
