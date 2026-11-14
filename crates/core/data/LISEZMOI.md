# Données du noyau

## `eff_large_wordlist.txt`

Liste longue de l'Electronic Frontier Foundation (« EFF's Long Wordlist », 2016), utilisée pour les phrases de passe (décision D8 du jalon 1).

| Élément | Valeur |
|---|---|
| Source | <https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt>, présentée sur <https://www.eff.org/dice> |
| Contenu | 7 776 lignes : cinq chiffres de dé (11111 à 66666), une tabulation, le mot ; 7 776 mots distincts, de 3 à 9 lettres minuscules (quatre contiennent un tiret) |
| Taille | 108 800 octets |
| Empreinte SHA-256 | `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e` |
| Licence | Creative Commons Attribution (CC BY), selon la page de droits d'auteur de l'EFF (<https://www.eff.org/copyright>) : l'origine de la liste doit être citée, ce que font ce fichier et les mentions des logiciels tiers |

Le fichier est conservé tel que publié, sans modification. Vérification du 11 novembre 2026 (le site de l'EFF n'est pas joignable depuis l'environnement de construction) :

- copie du fichier publié, tirée du paquet `diceware_wordlists` 1.2.3 (MIT ou Apache-2.0), qui le reproduit sous son chemin d'origine ;
- comparée mot pour mot à la liste du paquet `eff-wordlist` 1.0.3, constituée indépendamment ;
- comparée au site de l'EFF : même taille (108 800 caractères) et mêmes mots pour huit tirages (11111 `abacus`, 12345 `arousal`, 23456 `dispatch`, 34561 `ipad`, 45612 `prozac`, 55555 `spotter`, 61234 `suggest`, 66666 `zoom`).

L'essai `embedded_wordlist_is_the_published_eff_list` (`src/generator.rs`) vérifie l'empreinte, le nombre de mots et leur forme : une liste altérée fait échouer l'intégration continue.
