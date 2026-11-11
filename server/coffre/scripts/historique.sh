#!/bin/sh
# =============================================================================
# coffre — historique des coffres
#
# Exécuté en boucle par le conteneur « versions » (image officielle busybox).
# À chaque passage :
#   - copie horodatée de tout fichier de /dav/<utilisateur>/ qui a changé
#     depuis sa dernière copie, dans /versions/<utilisateur>/<fichier>/ ;
#   - suppression des copies de plus de RETENTION_DAYS jours, en gardant
#     toujours la plus récente de chaque fichier.
# Les fichiers sont des coffres déjà chiffrés : ce script ne les lit pas,
# il les compare octet par octet et les copie.
# =============================================================================
set -eu

DAV="${DAV_DIR:-/dav}"
OUT="${VERSIONS_DIR:-/versions}"
INTERVAL="${SNAPSHOT_INTERVAL:-900}"
KEEP_DAYS="${RETENTION_DAYS:-30}"

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) historique: $*"; }

# Dernière copie d'un fichier (les noms commencent par l'horodatage : l'ordre
# alphabétique est l'ordre chronologique).
derniere_copie() {
    ls -1 "$1" 2>/dev/null | grep -v '\.tmp$' | sort | tail -n 1 || true
}

copier() {
    for udir in "$DAV"/*/; do
        [ -d "$udir" ] || continue
        user=$(basename "$udir")
        for f in "$udir"*; do
            [ -f "$f" ] || continue
            name=$(basename "$f")
            case "$name" in
                .*|*.tmp|*~|*.lock) continue ;;   # fichiers temporaires des clients
            esac
            dest="$OUT/$user/$name"
            mkdir -p "$dest"
            last=$(derniere_copie "$dest")
            if [ -z "$last" ] || ! cmp -s "$f" "$dest/$last"; then
                stamp=$(date -u +%Y%m%dT%H%M%SZ)
                cp -p "$f" "$dest/$stamp.tmp"
                mv "$dest/$stamp.tmp" "$dest/${stamp}_$name"
                log "nouvelle version : $user/$name ($stamp)"
            fi
        done
    done
}

purger() {
    for d in "$OUT"/*/*/; do
        [ -d "$d" ] || continue
        newest=$(derniere_copie "$d")
        find "$d" -type f -mtime +"$KEEP_DAYS" | while read -r old; do
            [ "$(basename "$old")" = "$newest" ] && continue
            rm -f "$old"
            log "copie expirée supprimée : ${old#"$OUT"/}"
        done
    done
}

trap 'log "arrêt"; exit 0' TERM INT
log "démarrage : passage toutes les ${INTERVAL} s, conservation ${KEEP_DAYS} jours"
while true; do
    copier || log "erreur pendant la copie"
    purger || log "erreur pendant la purge"
    [ "${RUN_ONCE:-0}" = "1" ] && exit 0
    sleep "$INTERVAL" &
    wait $!
done
