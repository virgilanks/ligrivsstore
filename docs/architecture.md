# Architecture du noyau

Le noyau `ligrivsstore-core` regroupe tout ce qui touche aux secrets. Les applications (Windows en Tauri, Android en Kotlin, plus tard iPhone en Swift) l'appellent, sans réimplémenter le chiffrement, le format, la fusion ou la synchronisation.

## Modules

| Module | Rôle |
|---|---|
| `vault` | Coffre KDBX 4 : création, ouverture, enregistrement en KDBX 4.1, entrées (titre, adresse, identifiant, mot de passe, notes), historique, suppression suivie, fusion |
| `header` | Lecture stricte de l'en-tête sans la clé ; plafonds de dérivation vérifiés **avant** tout calcul |
| `kdf` | Politique de dérivation (Argon2id), calibrage, normalisation à l'enregistrement |
| `keyfile` | Fichiers clés : création au format XML 2.0 de KeePass, lecture, contrôle de la somme de contrôle |
| `storage` | Écriture atomique, relecture de contrôle, sauvegardes locales tournantes |
| `local` | Coffre local d'un terminal (`LocalVault`) et boucle de synchronisation |
| `sync` | Client WebDAV (`WebDavTransport`), état de synchronisation, trait `Transport` |
| `generator` | Mots de passe aléatoires (générateur du système, tirage sans biais) |
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
- `coffre.kdbx.synchro.json` : l'état de synchronisation (étiquette du serveur, modifications à envoyer, empreinte du dernier envoi), sans aucun secret.

Sous Unix, ces fichiers ne sont lisibles que par leur propriétaire (droits 600, dossier 700).

## Boucle de synchronisation

```text
┌─► 1. GET (If-None-Match : étiquette connue)
│      304 : rien de nouveau          404 : aucun coffre sur le serveur
│      200 : étiquette faible (W/) ? → attendre 1,1 s et relire (3 fois au plus)
│            empreinte = celle de notre dernier envoi ? → rien à fusionner
│            sinon : ouvrir (même clé, même coffre, sinon arrêt) puis fusionner
│   2. rien à envoyer → enregistrer la fusion éventuelle, retenir l'étiquette, fin
│   3. enregistrer localement (atomique, relu), puis PUT de ces mêmes octets
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
| Chaîne logicielle | Dépendances épinglées (`Cargo.lock`) ; licences et vulnérabilités connues contrôlées par `cargo-deny` ; actions GitHub épinglées par empreinte ; mises à jour proposées chaque semaine |

## Intégration dans les applications

- **Windows (J1)** : Tauri est en Rust ; l'application appelle directement `LocalVault`.
- **Android (J2)** : liaisons Kotlin générées par UniFFI 0.32.2, dans une caisse dédiée (`crates/ffi`), qui exposera une interface volontairement réduite.
- **iPhone (plus tard)** : mêmes liaisons, en Swift ; ouverture dans l'extension AutoFill avec `OpenLimits::ios_autofill()`.

Les appels qui dérivent une clé (ouvrir, enregistrer, synchroniser) prennent de 0,1 à 1 seconde. Les applications les exécutent hors du fil d'affichage.

## Mesures (11 novembre 2026, serveur de test 2 vCPU Xeon 2,1 GHz)

| Opération | Durée |
|---|---|
| Ouverture, Argon2id 32 Mio et 10 itérations | 135 à 150 ms |
| Ouverture, puis enregistrement vérifié | environ 320 ms |
| Calibrage pour 1 s | 45 itérations |
