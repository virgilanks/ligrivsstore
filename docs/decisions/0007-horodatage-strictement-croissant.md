# 0007 — Horodatage strictement croissant des versions d'une entrée

- Date : 11 novembre 2026
- Statut : adoptée

## Contexte

KDBX enregistre les dates à la seconde. La fusion ordonne les versions d'une entrée par date de modification. Avec la bibliothèque seule, deux modifications faites dans la même seconde portent la même date : leur ordre devient indéterminé.

Comportement mesuré de la bibliothèque 0.17.0 :

- deux terminaux qui modifient la même entrée dans la même seconde : la fusion garde la version de destination, range l'autre dans l'historique et le signale par un avertissement. Rien n'est perdu.
- deux versions d'un même terminal datées de la même seconde : elles sont conservées toutes deux, sans ordre fiable.

## Décision

- Chaque modification faite par le noyau porte une date strictement postérieure à la précédente : maintenant, ou une seconde après la version précédente si celle-ci est de la même seconde.
- Une modification qui ne change rien n'ajoute pas de version à l'historique.
- L'historique est limité à 10 versions par entrée, sauf réglage contraire du coffre, comme dans KeePass.
- Les avertissements de fusion sont remontés aux applications (`MergeReport::warnings`), qui pourront signaler à l'utilisateur une modification simultanée.

## Conséquences

- Testé : cinq modifications rapides restent ordonnées et se fusionnent sans avertissement ; deux modifications simultanées sur deux terminaux ne perdent aucune valeur (l'une est conservée, l'autre dans l'historique).
- Une horloge de terminal très en avance ferait gagner ses versions : limite propre au format, à documenter auprès des utilisateurs.
