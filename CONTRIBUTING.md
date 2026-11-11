# Contribuer

Le projet est mené en binôme. Claude écrit le code, les tests et la documentation. Hermann relit, compile, essaie sur ses appareils, fusionne et publie.

## Flux de travail

1. Chaque évolution part d'une branche nommée d'après le jalon : `jalon-1/extension-appairage`, par exemple.
2. Elle aboutit à une demande de fusion vers `main`, qui décrit le changement, les tests ajoutés et ce qu'il reste à essayer à la main.
3. L'intégration continue doit être verte : format, analyse statique, tests, interopérabilité KeePassXC, banc WebDAV, licences et vulnérabilités.
4. Hermann relit et fusionne. Aucune écriture directe sur `main`.

## Règles de code

- Rust stable, version fixée par `rust-toolchain.toml` ; `cargo fmt` et `cargo clippy -- -D warnings` sans exception.
- Aucun `unwrap`, `expect`, `panic` ou indexation non vérifiée hors des tests : les règles de l'espace de travail les interdisent.
- Pas de code `unsafe`.
- Identifiants en anglais ; commentaires, documentation, messages d'erreur et textes de l'outil en français.
- Toute fonction publique est documentée ; tout comportement de sécurité est couvert par un test.
- Les secrets transitent dans des types effacés à la destruction (`Zeroizing`) et ne s'affichent jamais (`Debug` masqué).

## Dépendances

- Toute nouvelle dépendance se justifie dans la demande de fusion. Elle doit avoir une licence permissive acceptée par `deny.toml`.
- La bibliothèque KDBX (`keepass`) est épinglée. Pour la mettre à jour : lire son journal des changements, mettre à jour l'épinglage, passer toute la suite, et consigner les constats dans `docs/decisions/0002-noyau-rust.md`.

## Messages de commit

En français, à l'impératif, une ligne de résumé (« Ajoute la reprise sur conflit 412 ») puis, si utile, un paragraphe d'explication.

## Décisions

Toute décision structurante fait l'objet d'une fiche dans `docs/decisions/` (contexte, décision, conséquences).
