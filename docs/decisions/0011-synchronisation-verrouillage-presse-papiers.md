# 0011 — Synchronisation, verrouillage et presse-papiers dans l'application Windows

- Date : 11 novembre 2026
- Statut : adoptée (semaine 2 du jalon 1)

## Contexte

La semaine 2 du jalon 1 livre deux postes synchronisés par le serveur « coffre ». Elle ajoute aussi le verrouillage automatique, le presse-papiers protégé, les sauvegardes et les phrases de passe générées (note de conception n° 3, sections 2.1, 5.3 et 5.4, et décisions D4 et D8).

Le noyau savait déjà synchroniser (jalon 0). Il fallait décider où ranger les identifiants du serveur et qui décide du moment des échanges. Il fallait aussi savoir comment apprendre le verrouillage de la session sans renoncer à l'interdiction du code `unsafe`, et ce que veut dire « restaurer » quand le coffre est fusionné entre plusieurs postes.

## Décision

### Identifiants du serveur : une entrée réservée du coffre (D4)

- L'adresse, le compte et le mot de passe du serveur sont rangés dans une entrée du coffre, marquée par l'attribut `ligrivsstore-role = synchronisation`. Ils sont chiffrés avec le reste et transmis aux autres postes par la fusion. Ils ne sont écrits nulle part ailleurs.
- L'application cache cette entrée de la liste et du compte des entrées. Les commandes ordinaires de l'interface (fiche, affichage, copie, modification, suppression) la refusent ; seul l'écran Synchronisation la modifie. KeePassXC la montre comme une entrée ordinaire, avec son attribut.
- Si deux postes la créent avant leur première fusion, la plus récemment modifiée l'emporte.
- Changer le compte ou le mot de passe lève la suspension qui suit un refus d'identifiants (voir plus bas).

### Moment des échanges : un pilote vérifiable

- Un « pilote » (`Autopilot`, paquet `ligrivsstore-app`) décide du moment des échanges. Il n'a ni fil ni horloge : la coquille l'interroge chaque seconde et exécute ses demandes. Ses règles se vérifient donc par des essais, sans attente :
  - synchronisation à l'ouverture, 10 secondes après la dernière modification, toutes les 15 minutes et à la demande ;
  - serveur injoignable ou en panne (codes 5xx) : nouvel essai après 2, puis 5, puis 15 minutes ;
  - refus d'identifiants : plus aucun essai avant une nouvelle saisie, même après un redémarrage. Le noyau garde cet état sur le disque, car CrowdSec bannit l'adresse 4 heures après cinq refus en rafale.
- Installation sur un nouveau PC : après un refus d'identifiants, l'application impose une minute de pause avant de recontacter le serveur.
- Délais réseau de l'application : 10 secondes pour la connexion, 30 secondes par échange. La session reste occupée pendant l'échange, en général moins de 3 secondes. Un verrouillage demandé à ce moment attend la fin de l'échange. L'interface suit l'état sans attendre, par un état observable distinct (`Monitor`).

### Verrouillage automatique

- Le coffre est verrouillé et sa clé effacée de la mémoire dans quatre cas :
  - après une inactivité dans l'application, 5 minutes par défaut, réglable de 1 à 60 ;
  - au verrouillage, à la fermeture ou à la déconnexion de la session Windows ;
  - à la mise en veille ;
  - à la fermeture de l'application.
- La mise en veille est détectée deux fois : par l'annonce de Windows (`PBT_APMSUSPEND`), et au réveil par un saut entre deux interrogations du pilote (plus de 30 secondes). Le second contrôle couvre la veille moderne et une annonce manquée.
- L'écran de déverrouillage indique le motif du verrouillage.

### Code `unsafe` : une seule exception, cantonnée

- Les notifications de session et d'alimentation exigent des appels directs à Windows. Ils sont regroupés dans le paquet `ligrivsstore-win`, seule exception à la règle `unsafe_code = "forbid"` du dépôt :
  - le code `unsafe` y est refusé (`deny`), sauf dans le module `systeme_windows` ;
  - chaque bloc ne contient qu'un appel, justifié par un commentaire `SAFETY` ; clippy l'exige (`undocumented_unsafe_blocks`, `multiple_unsafe_ops_per_block`) ;
  - ce module n'utilise que `windows-sys` 0.61.2, publié par Microsoft.
- Une fenêtre cachée, créée sur un fil dédié, reçoit `WM_WTSSESSION_CHANGE` et `WM_POWERBROADCAST`. Elle ne fait que transmettre l'événement au pilote.
- Clippy tourne aussi sous Windows dans l'intégration continue : le travail Linux ne voit pas ce code. Un essai y envoie de faux messages à la fenêtre et vérifie qu'ils arrivent, une fois chacun, et seulement ceux qui doivent verrouiller.

### Presse-papiers protégé

- La copie passe par le cœur, avec `clipboard-win` 5.4.3. Sa licence BSL-1.0, aussi permissive que MIT, est ajoutée à la liste admise.
- Trois formats sont posés avant le texte : `ExcludeClipboardContentFromMonitorProcessing`, et `CanIncludeInClipboardHistory` et `CanUploadToCloudClipboard` à 0. Si l'un échoue, rien n'est copié.
- Le presse-papiers est vidé après 30 secondes (réglable de 10 à 120), et seulement s'il contient toujours la copie : le numéro de séquence de Windows est revérifié, presse-papiers ouvert.
- L'intégration continue sous Windows vérifie les formats, l'effacement, et qu'une copie faite entre-temps par un autre programme est respectée.

### Sauvegardes : une restauration qui ne perd rien

- Une restauration remet chaque entrée de la sauvegarde dans son état d'alors, comme une modification ordinaire :
  - la version remplacée rejoint l'historique de l'entrée ;
  - la restauration se propage aux autres postes ;
  - une entrée supprimée depuis est recréée sous un nouvel identifiant, car sa suppression reste inscrite pour les autres postes ;
  - les entrées créées depuis sont conservées, et l'entrée réservée n'est jamais rétablie.
- Seuls les fichiers du dossier des sauvegardes du coffre sont acceptés. Une sauvegarde d'un autre coffre est refusée.
- L'état d'avant la restauration devient lui-même une sauvegarde : la restauration s'annule.
- Une synchronisation n'ajoute pas de sauvegarde, sauf quand elle fusionne des modifications venues du serveur. Sans fusion, elle envoie le fichier tel qu'enregistré, sans le réécrire. Le noyau reconnaît ce fichier à son empreinte SHA-256, gardée dans l'état de synchronisation ; un fichier modifié par un autre programme est réécrit avant l'envoi. Ainsi, la sauvegarde la plus récente reste l'état d'avant la dernière modification, même après la synchronisation qui la suit de 10 secondes. Défaut trouvé à la relecture de la recette (étape S2-7) et corrigé avant la fusion : chaque envoi réécrivait le fichier, si bien que la sauvegarde la plus récente reproduisait l'état courant et que sa restauration ne rétablissait rien.

### Phrases de passe (D8)

- Les phrases de passe sont tirées de la liste longue de l'EFF : 7 776 mots, soit 12,9 bits par mot ; 6 mots par défaut, soit environ 77,5 bits. Le séparateur est au choix ; majuscules initiales et chiffre sont facultatifs.
- La liste est intégrée telle que publiée et vérifiée par son empreinte SHA-256 (`crates/core/data/LISEZMOI.md`). Sa licence (CC BY) demande de citer l'EFF dans les mentions des logiciels tiers.
- L'écran de création propose une phrase de six mots, à noter sur papier avant de continuer.

## Conséquences

- Livrable vérifié automatiquement : l'essai `deux_postes` du paquet `ligrivsstore-app` joue deux postes contre le banc Apache, derrière le relais HTTPS, dans l'intégration continue. Le scénario :
  1. création, réglage et premier envoi sur le premier poste ;
  2. installation depuis le serveur sur le second ;
  3. modifications des deux côtés, puis convergence ;
  4. suppression synchronisée, puis restauration de la sauvegarde la plus récente, propagée à l'autre poste ;
  5. mauvais mot de passe, suspension, nouvelle saisie.
- Essai de l'application compilée, avec deux instances contre le banc : création, réglage, installation, ajout, synchronisation automatique 10 secondes après, fusion, suppression puis restauration propagées, verrouillage après une minute d'inactivité.
- Restent pour la suite :
  - le démarrage avec Windows et la zone de notification (semaine 3, avec le relais) ;
  - le changement de phrase de passe et la restauration d'un coffre illisible (jalon 3) ;
  - un essai automatique de l'application compilée (semaine 5).
