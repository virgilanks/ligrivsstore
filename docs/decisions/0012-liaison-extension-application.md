# 0012 — Liaison entre l'extension et l'application

- Date : 14 novembre 2026
- Statut : adoptée (semaine 3 du jalon 1)

## Contexte

La semaine 3 du jalon 1 livre une extension appairée qui liste les entrées du site ouvert (note de conception n° 3, sections 6.1 à 6.4). Elle ajoute aussi le démarrage avec Windows et la zone de notification, reportés de la semaine 2 (décision 0011).

La note fixait les grandes lignes : messagerie native de Chrome et d'Edge ; relais `ligrivsstore-pont.exe` ; canal nommé réservé au compte Windows ; appairage confirmé par une empreinte ; X25519, HKDF-SHA256 et AES-256-GCM ; compteur contre le rejeu ; correspondance des domaines dans le noyau. Restaient à fixer : la forme exacte des messages, l'ouverture des sessions, la confirmation de l'appairage, la protection du canal et des clés, et la vie de l'application en arrière-plan.

## Décision

### Chemin d'un message

```text
extension (service worker) ─ messagerie native ─► ligrivsstore-pont.exe ─ canal nommé ─► application
         JSON précédé de sa longueur (32 bits), 1 Mio au plus, dans les deux sens
```

- Le navigateur lance le relais à chaque liaison, avec l'origine de l'extension en premier argument. Le relais n'accepte que les extensions listées (`EXTENSION_IDS`, paquet `ligrivsstore-protocol`). Il annonce cette origine à l'application dans une première trame, puis transmet les trames sans les lire.
- Si l'application ne tourne pas, le relais la lance, cachée dans la zone de notification (`--arriere-plan`), et l'attend 15 secondes au plus. Le lancement ne lui transmet pas les tubes du navigateur : sous Windows, les entrées et sorties standard du relais cessent d'être héritables avant le lancement.
- Pour l'instant, une seule extension est admise : la version de développement, d'identifiant `pbjfabapbnileccikicpifdnhkocnlbb`. Cet identifiant découle de la clé publique écrite dans son manifeste ; la clé privée n'a pas été conservée, car le chargement en mode développeur n'en a pas besoin. Les identifiants du Chrome Web Store et d'Edge Add-ons s'ajouteront à la publication (D2).

### Canal nommé

- Nom : `\\.\pipe\ligrivsstore-<SID du compte>`, un canal par compte Windows.
- Liste de contrôle d'accès explicite et protégée : `D:P(A;;GA;;;<SID>)`. Seul ce compte y accède, pas les autres comptes du PC.
- Créé en première instance (`FILE_FLAG_FIRST_PIPE_INSTANCE`) : si un autre programme a pris le nom avant l'application, la création échoue, au lieu de partager le canal. Les clients distants sont refusés.
- Paquet `interprocess` 2.4.8, appelé sans code `unsafe` de notre part. Le SID du compte vient du module `systeme_windows` (décision 0011), qui garde le monopole du code `unsafe`.
- Hors de Windows, pour le développement et les essais, le canal est un socket Unix, dans un dossier en 0700 et en 0600.

### Appairage, une fois par navigateur

1. L'extension tire une paire de clés X25519 avec l'API Web Crypto. Sa clé privée est non exportable et reste dans le navigateur (IndexedDB).
2. L'application a sa propre paire. Sa clé privée est protégée par DPAPI, liée au compte Windows (`cle-appairage.bin`). Si elle devient illisible, une nouvelle clé la remplace et les appairages sont oubliés.
3. Les deux côtés affichent la même empreinte : SHA-256 d'un libellé et des deux clés publiques, lue en six groupes de cinq chiffres, soit environ 100 bits.
4. L'utilisateur la compare et confirme dans l'application. Il dit aussi, dans l'extension, que l'empreinte affichée par l'application était la même : l'appairage n'est retenu qu'après ces deux confirmations.

Cette double confirmation protège d'un programme qui se ferait passer pour l'application sur le canal. Un tel programme pourrait répondre « confirmé » à l'extension ; mais l'application n'aurait rien affiché, ou une autre empreinte.

Trois demandes au plus attendent en même temps, deux minutes au plus chacune. Les navigateurs appairés sont retenus dans `navigateurs.json`, à côté des réglages : nom, origine, clé publique, empreinte, dates. Ces données ne sont pas secrètes.

### Sessions

- À chaque liaison, l'extension envoie sa clé permanente et une clé éphémère. L'application vérifie que la clé permanente est appairée, depuis la même origine. Elle répond par sa propre clé éphémère et par un premier message chiffré, qui prouve qu'elle détient sa clé privée.
- Clés de session : HKDF-SHA256 appliqué aux deux échanges Diffie-Hellman, permanent-permanent (qui authentifie les deux parties) et éphémère-éphémère (qui rend chaque session unique). Le sel et l'information de HKDF lient les quatre clés publiques.
- Cette construction précise la note n° 3. Chaque session a ses propres clés : les compteurs repartent de zéro sans risque de réutiliser un nonce, et rien n'est à conserver entre deux sessions. Les sessions passées restent protégées si une clé permanente fuit un jour.
- AES-256-GCM, une clé par sens. Le nonce porte le sens et un compteur ; le compteur reçu doit être exactement le suivant. Tout message rejoué, supprimé, réordonné, altéré, tronqué ou renvoyé à son auteur est refusé, et la liaison se ferme.
- Les vecteurs d'essai `crates/protocol/tests/vecteurs.json` sont vérifiés par le paquet Rust et par l'extension (Web Crypto). Une mise en œuvre indépendante, écrite pour la vérification, a aussi retrouvé les mêmes clés, empreinte et chiffrés.

### Requêtes de la semaine 3

| Requête | Réponse |
|---|---|
| `status` | Coffre verrouillé ou non |
| `entries` (adresse de la page) | Entrées de la page, de la plus proche à la plus éloignée : titre, identifiant, proximité, page non chiffrée. Jamais de mot de passe : le remplissage arrive en semaine 4 |
| `show` | L'application montre sa fenêtre, pour déverrouiller le coffre |

- L'adresse de la page vient de l'onglet, lu par le service worker, jamais de la page.
- Un navigateur révoqué est coupé au message suivant.
- Les requêtes de l'extension ne repoussent pas le verrouillage automatique.

### Correspondance des domaines

Module `domain` du noyau, que l'application Android reprendra.

- Liste des suffixes publics : paquet `psl`, parties ICANN et privée comprises, compilée dans le programme. La liste est publiée presque chaque jour : la version est figée (2.1.251, celle de la note n° 3), puis mise à jour par Dependabot et l'intégration continue.
- Une entrée correspond si elle a le même hôte que la page, ou un autre sous-domaine du même domaine enregistrable. Ce dernier cas est signalé à l'utilisateur.
- Jamais d'autre domaine, même ressemblant, ni de suffixe public partagé (`alice.github.io` et `bob.github.io`).
- Adresses IP, `localhost` et noms sans domaine : hôte et port exacts seulement.
- Page en `http://` : jamais d'entrée en `https://` ; une entrée en `http://` est proposée, signalée non chiffrée.
- Une entrée sans adresse, ou dans un autre schéma (`ssh://`, `androidapp://`…), n'est jamais proposée.
- Les noms internationalisés sont comparés en Punycode : une lettre cyrillique qui imite une lettre latine donne un autre domaine.

### Application en arrière-plan

- L'application vit dans la zone de notification, avec un menu : ouvrir, verrouiller, quitter.
- Fermer la fenêtre la cache sans verrouiller le coffre : l'extension peut encore lister les entrées. Le délai d'inactivité continue de courir.
- « Quitter » verrouille le coffre et arrête l'application. La règle de la décision 0011 (verrouillage à la fermeture) vaut donc pour la sortie de l'application.
- Démarrage avec Windows : option des réglages, désactivée par défaut, par `tauri-plugin-autostart` 2.7.0. L'application démarre alors cachée, coffre verrouillé. Sans cette option, l'extension la démarre quand elle en a besoin.
- Une seule instance : un second lancement ramène la fenêtre de l'application déjà lancée, sauf s'il est fait en arrière-plan (relais, démarrage avec Windows). Dans ce cas, rien ne s'affiche.

### Déclaration du relais aux navigateurs

- Le manifeste `com.ligrivs.ligrivsstore.json` est livré avec l'installateur, à côté du relais. Son chemin vers le relais est relatif, ce que Chrome admet sous Windows.
- Les clés `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.ligrivs.ligrivsstore` et `HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.ligrivs.ligrivsstore` pointent vers ce manifeste.
- L'installateur écrit ces clés (étape NSIS ajoutée), et l'application les vérifie à chaque démarrage (paquet `winreg` 0.56.0, sans code `unsafe`). Le tout reste sans droits d'administrateur.
- La désinstallation retire les deux clés et le démarrage avec Windows.

### Extension (squelette)

- Manifest V3 ; permissions `nativeMessaging` et `activeTab` seulement.
- L'accès à toutes les pages (D6) n'arrivera qu'avec l'icône dans les champs, en semaine 4. D'ici là, la fenêtre de l'extension lit l'adresse de l'onglet quand l'utilisateur clique sur son icône.
- Aucune dépendance embarquée : esbuild 0.28.2 et TypeScript 6.0.3 servent à la construction seulement. TypeScript reste dans la même version majeure que l'application (décision 0010).
- Rien n'est conservé, sauf la clé d'appairage et l'empreinte (IndexedDB). Le contenu des pages est construit sans `innerHTML`.

### Licences

- `0BSD` admise pour deux paquets nommés, dépendances d'`interprocess` : `recvmsg`, livré sous Windows, et `doctest-file`, une macro de compilation. Cette licence est sans aucune condition, plus permissive encore que MIT.
- `x25519-dalek` et `curve25519-dalek` sont en BSD-3-Clause, licence déjà admise.

## Conséquences

- Nouveaux paquets :
  - `ligrivsstore-protocol` : trames, messages, chiffrement ;
  - `ligrivsstore-bridge` : le relais `ligrivsstore-pont`.
- Modules ajoutés :
  - `liaison` et `navigateurs` dans `ligrivsstore-app` ;
  - `canal`, DPAPI et SID dans `ligrivsstore-win` ;
  - `domain` dans le noyau.
- L'application passe à 32 commandes, avec l'onglet « Navigateurs » et la demande d'appairage en surimpression.
- Essais automatiques :
  - protocole : 16 essais Rust, 6 essais de l'extension sur les vecteurs communs ;
  - liaison de bout en bout par le canal : 7 ;
  - relais : 4 ; canal : 3 sous Linux, 4 sous Windows ;
  - DPAPI et SID, sous Windows ;
  - correspondance des domaines : 8.
- Essai de bout en bout sous Linux (`extension/bout-en-bout/essai.mjs`) : Chromium avec l'extension, le relais déclaré, l'application compilée sous un écran virtuel.
- Restent pour la suite :
  - icône dans les champs, remplissage et Edge (semaine 4) ;
  - enregistrement des nouveaux identifiants (semaine 5) ;
  - identifiants des boutiques dans `EXTENSION_IDS` et dans le manifeste du relais (avant la bêta) ;
  - signature du relais, que SmartScreen ou un antivirus pourraient bloquer (D3, risque noté dans la note n° 3).
