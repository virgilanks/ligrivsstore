# Serveur « coffre » — copie de référence

Le dossier `coffre/` reprend les livrables du service « coffre » du projet KEEPASS : fiche de déploiement (`service.yaml`), `compose.yaml`, configuration Apache et scripts d'exploitation.

- Le déploiement sur l'infrastructure Zanzibar est fait par la conversation « infra », à partir de ces fichiers et du dossier de conception (v1.1).
- Ici, ils servent au banc de test : `scripts/banc-webdav.sh` démarre Apache avec exactement ces directives, chemins adaptés. La synchronisation est ainsi testée contre la configuration qui sera déployée.
- Toute modification de la configuration du serveur doit être répercutée dans les livrables du projet, puis redéployée par la conversation « infra ».
