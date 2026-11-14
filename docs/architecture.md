# Architecture

Le noyau `ligrivsstore-core` regroupe tout ce qui touche aux secrets. Les applications (Windows en Tauri, Android en Kotlin, plus tard iPhone en Swift) l'appellent, sans réimplémenter le chiffrement, le format, la fusion ou la synchronisation.

## Modules

| Module | Rôle |
|---|---|
| `vault` | Coffre KDBX 4 : création, ouverture, enregistrement en KDBX 4.1, entrées (titre, adresse, identifiant, mot de passe, notes), historique, suppression suivie, fusion, entrées réservées (attribut `ligrivsstore-role`), restauration des entrées d'une sauvegarde |
| `header` | Lecture stricte de l'en-tête sans la clé ; plafonds de dérivation vérifiés **avant** tout calcul |
| `kdf` | Politique de dérivation (Argon2id), calibrage, normalisation à l'enregistrement |
| `keyfile` | Fichiers clés : création au format XML 2.0 de KeePass, lecture, contrôle de la somme de contrôle |
| `storage` | Écriture atomique, relecture de contrôle, sauvegardes locales tournantes |
| `local` | Coffre local d'un terminal (`LocalVault`) et boucle de synchronisation |
| `sync` | Client WebDAV (`WebDavTransport`), état de synchronisation, trait `Transport` |
| `generator` | Mots de passe et phrases de passe (liste longue de l'EFF) aléatoires (générateur du système, tirage sans biais) |
| `domain` | Correspondance entre la page ouverte et l'adresse des entrées : liste des suffixes publics, domaines ressemblants écartés (décision 0012) |
| `error` | Erreurs en français ; une variante par cas, pour que chaque application affiche son propre texte |

La lecture et l'écriture du format reposent sur la bibliothèque `keepass` 0.17.0 (licence MIT), épinglée et encadrée (voir les décisions 0002 et 0006).

## Cycle de vie d'un coffre sur un terminal

```text
LocalVault::create / open / clone_from_remote
        │
        ├─ vault_mut() : ajouter, modifier, supprimer des entrées
        ├─ save()      : sérialiser → écrire en fichier temporaire → relire → rouvrir avec la clé
        │                → sauvegarder la version précédente → renommer (atomique)
        └─ sync()      : boucle ci-dessous
```

Fichiers d'un coffre `coffre.kdbx` :

- `coffre.kdbx` : le coffre chiffré ;
- `coffre.kdbx.sauvegardes/` : les dix versions précédentes, chiffrées comme le coffre ;
- `coffre.kdbx.synchro.json` : l'état de synchronisation (étiquette du serveur, modifications à envoyer, empreintes du dernier envoi et du dernier fichier écrit), sans aucun secret.

Sous Unix, ces fichiers ne sont lisibles que par leur propriétaire (droits 600, dossier 700).

## Boucle de synchronisation

```text
┌─► 1. GET (If-None-Match : étiquette connue)
│      304 : rien de nouveau          404 : aucun coffre sur le serveur
│      200 : étiquette faible (W/) ? → attendre 1,1 s et relire (3 fois au plus)
│            empreinte = celle de notre dernier envoi ? → rien à fusionner
│            sinon : ouvrir (même clé, même coffre, sinon arrêt) puis fusionner
│   2. rien à envoyer → enregistrer la fusion éventuelle, retenir l'étiquette, fin
│   3. PUT du fichier local : tel quel s'il contient déjà le coffre en mémoire
│      (écrit par le noyau, empreinte inchangée) ; sinon (fusion, modification
│      non enregistrée), l'enregistrer d'abord (atomique, relu), puis PUT de
│      ces mêmes octets. Sans fusion, aucune réécriture, donc aucune sauvegarde
│      en double : la plus récente reste l'état d'avant la dernière modification
│      If-Match : étiquette   (ou If-None-Match : * s'il n'existe pas)
│      2xx : fin (l'étiquette renvoyée, faible, n'est pas conservée)
└── 412 : un autre terminal a écrit entre-temps → recommencer (5 tentatives au plus)

401 à n'importe quelle étape : synchronisation suspendue (état enregistré)
jusqu'à LocalVault::accept_new_credentials — CrowdSec bannit l'adresse
4 heures après cinq échecs en rafale.
```

## Règles du serveur « coffre » (revue infra du 11 novembre 2026)

Le noyau les applique avant toute requête (décision 0008) :

| Règle du serveur | Application par le noyau |
|---|---|
| Coffres à la racine de `/dav/<compte>/`, pas de sous-dossier (historique, MKCOL refusé) | Adresse `/dav/<compte>/<coffre>.kdbx` exigée, `<compte>` égal au compte WebDAV |
| Fichiers temporaires (`.tmp`, `~`, `.lock`, nom commençant par un point) non historisés | Noms refusés ; extension `.kdbx` exigée |
| 50 Mo au plus par fichier | Envoi refusé localement au-delà (`MAX_UPLOAD_BYTES`) |
| CrowdSec : cinq échecs avec identifiants en rafale, bannissement de 4 heures | Identifiants à chaque requête ; suspension après un refus |

Garanties vérifiées par les tests :

- aucun envoi ne remplace une version que ce terminal n'a pas fusionnée ;
- un coffre distant illisible, chiffré avec une autre clé ou d'une autre identité n'est jamais écrasé ;
- deux terminaux qui créent le coffre en même temps ne s'écrasent pas (création conditionnelle) ;
- une interruption à n'importe quel moment laisse un fichier local complet et lisible.

## Sécurité

| Sujet | Disposition |
|---|---|
| Format | KDBX 4.1, AES-256 (ou ChaCha20 / Twofish conservés), chiffrement interne ChaCha20 |
| Dérivation | Argon2id 1.3, 2 voies, 32 Mio à la création ; 32 à 64 Mio à l'enregistrement (limite de l'AutoFill d'iOS) ; itérations calibrées, jamais moins de 4 ; les réglages par défaut de la bibliothèque (Argon2d, 1 Mio) ne sont jamais écrits |
| Fichiers hostiles | En-tête relu de façon stricte avant tout calcul (plafonds : 1 Gio, 1 000 itérations, 16 voies, 100 millions de tours AES, 64 Mio de fichier) ; toute panique de la bibliothèque est convertie en erreur |
| Réseau | `https://` obligatoire (`http://` admis vers la machine locale seulement, pour les tests) ; autorités publiques seulement, sauf autorité explicite (banc, serveur privé) ; aucun identifiant dans l'adresse ; aucune redirection suivie ; téléchargement plafonné à 64 Mio, envoi à 50 Mo ; délais d'attente |
| Bordure | Cloudflare termine le chiffrement HTTPS : il voit le mot de passe WebDAV et les fichiers, chiffrés et authentifiés par KDBX. Le mot de passe WebDAV est distinct de la phrase de passe du coffre et renouvelable |
| Refus d'identifiants | Synchronisation suspendue après un 401, jusqu'à une nouvelle saisie (CrowdSec) |
| Mémoire | Clé du coffre, mots de passe saisis et générés, identifiants WebDAV : effacés à la destruction (`zeroize`) ; affichage masqué dans les journaux de débogage |
| Fichiers locaux | Écriture atomique et relecture avant tout envoi ; dix sauvegardes ; droits restreints. Sous Windows, si un autre programme tient le fichier (antivirus, OneDrive, indexation), le remplacement est retenté pendant près de 2 secondes |
| Fichiers clés | Créés au format XML 2.0 de KeePass (32 octets aléatoires et somme de contrôle) ; un fichier XML 2.0 endommagé est signalé comme tel ; les autres fichiers restent acceptés selon les règles de KeePass (décision 0009) |
| Chaîne logicielle | Dépendances épinglées (`Cargo.lock`, `package-lock.json`) ; licences et vulnérabilités connues contrôlées par `cargo-deny` et `npm audit` ; actions GitHub épinglées par empreinte ; mises à jour proposées chaque semaine |
| Interface de l'application | Liste fermée de commandes, permissions de Tauri, motif d'isolation, politique de contenu stricte (décision 0010) ; le coffre déverrouillé et sa clé restent dans le processus Rust ; l'entrée réservée est refusée aux commandes ordinaires |
| Verrouillage | Inactivité, session Windows, mise en veille, fermeture ; la clé est alors effacée de la mémoire (décision 0011) |
| Presse-papiers | Copie par le cœur, hors de l'historique (Windows + V) et du presse-papiers cloud ; effacée après 30 secondes si elle n'a pas été remplacée |
| Code `unsafe` | Interdit partout, sauf dans le module `systeme_windows` du paquet `ligrivsstore-win` : appels à Windows (session, veille, SID du compte, DPAPI, héritage des descripteurs), un par bloc, chacun justifié ; clippy sous Windows dans l'intégration continue |
| Liaison avec l'extension | Relais réservé aux extensions listées ; canal nommé du compte (liste de contrôle d'accès explicite, première instance) ; appairage confirmé des deux côtés par une empreinte de six groupes de chiffres ; sessions X25519 (permanente et éphémère), HKDF-SHA256, AES-256-GCM, compteur exact ; clé de l'application protégée par DPAPI ; aucun mot de passe transmis en semaine 3 (décision 0012) |
| Correspondance des domaines | Même hôte, ou autre sous-domaine du même domaine enregistrable (signalé) ; jamais un domaine ressemblant ni un suffixe public partagé ; adresses IP et `localhost` : hôte et port exacts ; jamais d'entrée `https://` sur une page `http://` |

## Application Windows (jalon 1)

```text
apps/windows/src        Svelte 5 : écrans et formulaires ; ne conserve aucun secret
      │  32 commandes → cadre d'isolation (même liste) → message chiffré → permissions de Tauri
apps/windows/src-tauri  Tauri 2 : relaie chaque commande vers la session, dans une tâche à part ;
      │                 fil « pilote » : interroge l'Autopilot chaque seconde et exécute ses demandes ;
      │                 zone de notification ; démarrage avec Windows ; déclaration du relais
crates/app              ligrivsstore-app : session, pilote, état observable, réglages, messages, erreurs ;
      │                 liaison avec l'extension (appairage, sessions chiffrées), navigateurs appairés
      │        ├──────► crates/protocol (ligrivsstore-protocol) : trames, messages, chiffrement
      │        └──────► crates/win (ligrivsstore-win) : session Windows, veille, presse-papiers, canal, DPAPI
crates/core             ligrivsstore-core : LocalVault (coffre, dérivation, stockage, synchronisation), domaines
```

| Commandes | Rôle |
|---|---|
| `status`, `default_paths` | État de la session ; emplacements proposés à la création |
| `create_vault`, `open_vault`, `lock_vault`, `forget_vault` | Cycle de vie du coffre |
| `list_entries`, `get_entry`, `reveal_password` | Liste filtrée, fiche sans mot de passe, mot de passe sur demande |
| `save_entry`, `delete_entry`, `retry_save` | Chaque modification est enregistrée aussitôt (écriture atomique, relue) ; en cas d'échec, l'application le signale et propose de réessayer |
| `copy_field` | Copie d'un identifiant ou d'un mot de passe par le cœur, hors de l'historique du presse-papiers et du cloud, effacée après le délai réglé |
| `install_from_server` | Installation, sur un nouveau PC, du coffre présent sur le serveur |
| `get_sync_settings`, `configure_sync`, `sync_now` | Réglage de la synchronisation (rangé dans l'entrée réservée du coffre) ; échange immédiat |
| `activity`, `ping_activity` | État observable (verrouillage, synchronisation), relu toutes les 2 secondes sans attendre la session ; activité de l'utilisateur |
| `list_backups`, `restore_backup` | Les 10 sauvegardes locales ; restauration de leurs entrées |
| `get_preferences`, `save_preferences` | Délai de verrouillage (1 à 60 minutes) et d'effacement du presse-papiers (10 à 120 secondes) |
| `generate_password`, `generate_passphrase`, `passphrase_strength` | Générateurs ; robustesse d'une phrase de passe (zxcvbn) |
| `list_browsers`, `pending_pairings`, `decide_pairing`, `revoke_browser` | Navigateurs appairés ; demandes d'appairage en attente, confirmées ou refusées ; révocation |
| `get_autostart`, `set_autostart` | Démarrage avec Windows, caché dans la zone de notification |

Le pilote (`Autopilot`) décide du moment des échanges et des verrouillages, sans fil ni horloge propres (décision 0011) :

| Événement | Effet |
|---|---|
| Ouverture du coffre | Synchronisation immédiate |
| Modification | Synchronisation 10 secondes après la dernière |
| Toutes les 15 minutes, ou à la demande | Synchronisation |
| Serveur injoignable | Nouvel essai après 2, 5, puis 15 minutes |
| Identifiants refusés | Plus aucun essai avant une nouvelle saisie (CrowdSec) |
| Inactivité dans l'application (5 minutes par défaut) | Verrouillage |
| Session Windows verrouillée, fermée ou déconnectée ; mise en veille (annoncée, ou constatée au réveil) | Verrouillage |
| Délai d'effacement atteint, presse-papiers inchangé | Presse-papiers vidé |

Fichiers sur le PC (emplacements proposés par défaut) :

- coffre : `Documents\ligrivsstore\coffre.kdbx`, avec ses sauvegardes et son état de synchronisation ;
- fichier clé : `%LOCALAPPDATA%\ligrivsstore-cles\coffre.keyx`, hors de OneDrive, donc jamais à côté du coffre sur un serveur, et hors du dossier de l'application, que la désinstallation peut effacer ;
- réglages : `%APPDATA%\com.ligrivs.ligrivsstore\reglages.json`, qui ne retient que l'emplacement du dernier coffre, celui de son fichier clé et les deux délais ;
- identifiants du serveur : dans le coffre lui-même (entrée réservée), jamais ailleurs ;
- navigateurs appairés : `navigateurs.json`, à côté des réglages (clés publiques, empreintes, dates : rien de secret) ;
- clé d'appairage de l'application : `cle-appairage.bin`, à côté des réglages, chiffrée par DPAPI pour le seul compte Windows.

## Extension et liaison (jalon 1, semaine 3)

```text
extension Chrome / Edge         service worker : seul à parler à l'application ; lit l'adresse
(extension/, Manifest V3)       de la page dans l'onglet ; clé d'appairage non exportable (IndexedDB)
      │  messagerie native : JSON précédé de sa longueur, 1 Mio au plus
ligrivsstore-pont.exe           relais (crates/bridge) : origine de l'extension vérifiée ; lance
      │                         l'application si besoin ; transmet sans lire
      │  canal nommé \\.\pipe\ligrivsstore-<SID> (compte seul, première instance)
application                     appairage, sessions chiffrées, requêtes : état, entrées de la page, fenêtre
```

| Étape | Messages (en clair, sauf `msg` et `welcome`) |
|---|---|
| Ouverture de la liaison | `bridge` (origine de l'extension, par le relais) |
| Appairage | `pair` → `pair-pending` (clé de l'application) → `pair-result` (confirmé, refusé, expiré) |
| Session | `hello` (clés permanente et éphémère) → `welcome` (clé éphémère, premier message chiffré) |
| Requêtes | `msg` ↔ `msg` : `status`, `entries`, `show`, et leurs réponses |
| Refus | `error` (version, origine, navigateur non appairé…) |

Les vecteurs d'essai communs (`crates/protocol/tests/vecteurs.json`) garantissent que l'extension (Web Crypto) et l'application (Rust) chiffrent à l'identique. Le détail est dans la décision 0012.

Le cloisonnement de l'interface, la création d'un coffre et les licences sont décrits dans la décision 0010.

## Intégration dans les applications

- **Windows (J1)** : Tauri est en Rust ; la coquille appelle `ligrivsstore-app`, qui pilote `LocalVault`.
- **Android (J2)** : liaisons Kotlin générées par UniFFI 0.32.2, dans une caisse dédiée (`crates/ffi`), qui exposera une interface volontairement réduite.
- **iPhone (plus tard)** : mêmes liaisons, en Swift ; ouverture dans l'extension AutoFill avec `OpenLimits::ios_autofill()`.

Les appels qui dérivent une clé (ouvrir, enregistrer, synchroniser) prennent de 0,1 à 1 seconde. Les applications les exécutent hors du fil d'affichage.

## Mesures (11 novembre 2026, serveur de test 2 vCPU Xeon 2,1 GHz)

| Opération | Durée |
|---|---|
| Ouverture, Argon2id 32 Mio et 10 itérations | 135 à 150 ms |
| Ouverture, puis enregistrement vérifié | environ 320 ms |
| Calibrage pour 1 s | 45 itérations |
