# 0006 — Contrôle de l'en-tête avant ouverture, panique convertie en erreur

- Date : 11 novembre 2026
- Statut : adoptée

## Contexte

La bibliothèque KDBX applique les paramètres de dérivation inscrits dans le fichier **avant** de pouvoir vérifier la clé. Un fichier déposé par un serveur ou un intermédiaire compromis pourrait donc :

- demander des gibioctets de mémoire (arrêt de l'application faute de mémoire) ;
- demander des milliards d'itérations (application figée) ;
- demander des milliers de voies, donc autant de fils d'exécution ;
- faire paniquer la bibliothèque. Par exemple, une valeur numérique trop courte dans le dictionnaire des paramètres est lue sans contrôle de longueur.

Mesure au jalon 0 : sur 3 000 fichiers altérés au hasard, la bibliothèque seule panique de 2 à 7 fois selon les essais (0,07 à 0,23 %, sept essais), toujours dans l'en-tête.

## Décision

- Avant toute ouverture, le noyau relit l'en-tête de façon stricte (`header::inspect`). Il refuse clés en double, types ou longueurs inattendus et données après la fin du dictionnaire. Il compare ensuite les paramètres à des plafonds (`OpenLimits`) : 1 Gio de mémoire, 1 000 itérations, 16 voies, 100 millions de tours d'AES-KDF et 64 Mio de fichier. Pour l'AutoFill d'iOS, le plafond de mémoire descend à 64 Mio.
- L'appel à la bibliothèque est enveloppé : une panique éventuelle devient une erreur « fichier malformé », sans arrêter l'application.
- La lecture stricte empêche qu'un même fichier soit compris d'une façon par le contrôle et d'une autre par la bibliothèque. Une clé en double, par exemple, pourrait sinon faire valider une valeur et appliquer l'autre.

## Conséquences

- Avec le noyau, les 3 000 fichiers altérés donnent tous une erreur ordinaire, à chaque essai. Toutes les paniques observées sont évitées dès le contrôle d'en-tête : aucune n'a eu besoin du garde-fou.
- Les tests aléatoires (proptest à chaque compilation, libFuzzer chaque semaine) vérifient qu'aucune entrée ne provoque d'arrêt. La cible `ouvrir_coffre` appelle la bibliothèque sans garde-fou, pour détecter toute panique qui franchirait le contrôle.
- Les cas trouvés seront signalés à l'auteur de la bibliothèque.
