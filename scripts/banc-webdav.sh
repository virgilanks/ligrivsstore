#!/usr/bin/env bash
# =============================================================================
# Banc WebDAV local : le serveur « coffre » (configuration de server/coffre,
# chemins adaptés) sur Apache 2.4, pour les tests de synchronisation.
#
#   sudo scripts/banc-webdav.sh demarrer   démarre le banc et crée deux comptes
#   sudo scripts/banc-webdav.sh arreter    arrête le banc et efface ses fichiers
#
# Prérequis : Apache 2.4 (paquets apache2 et apache2-utils), droits root.
# Après le démarrage, les variables des tests sont dans $LGS_BANC_DIR/env :
#   set -a; . /tmp/lgs-banc-webdav/env; set +a
#   cargo test -p ligrivsstore-core --test webdav
#
# Les mots de passe des comptes de test sont générés à chaque démarrage et
# n'existent que sur ce banc.
# =============================================================================
set -euo pipefail

RACINE_DEPOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="$RACINE_DEPOT/server/coffre"
BANC="${LGS_BANC_DIR:-/tmp/lgs-banc-webdav}"
PORT="${LGS_BANC_PORT:-18081}"
MODULES="${APACHE_MODULES_DIR:-/usr/lib/apache2/modules}"
APACHE="${APACHE_BIN:-/usr/sbin/apache2}"

[ "$(id -u)" = "0" ] || { echo "À lancer en root (sudo)." >&2; exit 1; }

arreter() {
    pkill -f "$APACHE -f $BANC/apache2/conf/httpd.conf" 2>/dev/null || true
    sleep 0.5
    rm -rf "$BANC"
}

demarrer() {
    arreter
    mkdir -p "$BANC/apache2/conf" "$BANC/apache2/htdocs" "$BANC/run"
    cp -r "$SOURCE" "$BANC/site"
    sed -e "s/^EDGE01_IP=.*/EDGE01_IP=127.0.0.1/" -e "s/^PORT_HTTP=.*/PORT_HTTP=$PORT/" \
        "$SOURCE/.env.example" > "$BANC/site/.env"
    ln -s "$MODULES" "$BANC/apache2/modules"
    cp /etc/mime.types "$BANC/apache2/conf/mime.types"
    cp "$SOURCE/config/healthz.txt" "$BANC/apache2/htdocs/"

    # Mêmes directives que la configuration livrée ; seuls les chemins, le port
    # et les journaux changent.
    sed -e "s#/usr/local/apache2/conf/auth/htpasswd#$BANC/site/auth/htpasswd#g" \
        -e "s#/usr/local/apache2#$BANC/apache2#g" \
        -e "s#/srv/keepass/dav#$BANC/site/data/dav#g" \
        -e "s#/srv/keepass/versions#$BANC/site/data/versions#g" \
        -e "s#/var/lib/davlock#$BANC/site/data/davlock#g" \
        -e "s#^Listen 8080#Listen 127.0.0.1:$PORT#" \
        -e "s#^PidFile /tmp/httpd.pid#PidFile $BANC/run/httpd.pid#" \
        -e "s#^DefaultRuntimeDir /tmp#DefaultRuntimeDir $BANC/run#" \
        -e "s#^ErrorLog /proc/self/fd/2#ErrorLog $BANC/run/error.log#" \
        -e "s#^CustomLog /proc/self/fd/1 coffre#CustomLog $BANC/run/access.log coffre#" \
        "$SOURCE/config/httpd.conf" > "$BANC/apache2/conf/httpd.conf"
    ln -s "$BANC/site/auth/utilisateurs" "$BANC/apache2/conf/utilisateurs"
    chown -R www-data:www-data "$BANC/run"
    chmod -R a+rX "$BANC/apache2"
    chmod 755 "$BANC" "$BANC/site"

    # Comptes de test, créés par le script d'exploitation du service.
    cd "$BANC/site"
    export HTPASSWD_BIN=/usr/bin/htpasswd RACINE_CONTENEUR="$BANC/site/data" HTTPD_RELOAD_CMD=true
    local mdp1 mdp2
    mdp1=$(bash scripts/utilisateurs.sh ajouter recette1 | sed -n 's/.*Mot de passe : //p')
    mdp2=$(bash scripts/utilisateurs.sh ajouter recette2 | sed -n 's/.*Mot de passe : //p')
    [ -n "$mdp1" ] && [ -n "$mdp2" ] || { echo "Création des comptes impossible." >&2; exit 1; }

    runuser -u www-data -- env PUBLIC_HOSTNAME=coffre.test EDGE01_IP=127.0.0.1 \
        "$APACHE" -f "$BANC/apache2/conf/httpd.conf"
    for _ in $(seq 1 50); do
        if curl -sf "http://127.0.0.1:$PORT/healthz" | grep -q '^ok'; then
            break
        fi
        sleep 0.1
    done
    curl -sf "http://127.0.0.1:$PORT/healthz" | grep -q '^ok' || {
        echo "Le banc ne répond pas ; journal :" >&2
        cat "$BANC/run/error.log" >&2 || true
        exit 1
    }

    umask 077
    cat > "$BANC/env" <<EOF
LGS_TEST_WEBDAV_URL=http://127.0.0.1:$PORT/dav/recette1/
LGS_TEST_WEBDAV_USER=recette1
LGS_TEST_WEBDAV_PASSWORD=$mdp1
LGS_TEST_WEBDAV_USER2=recette2
LGS_TEST_WEBDAV_PASSWORD2=$mdp2
EOF
    # Lisible par l'utilisateur qui a lancé sudo (les tests ne tournent pas en root).
    if [ -n "${SUDO_USER:-}" ]; then
        chown "$SUDO_USER" "$BANC/env"
    fi
    echo "Banc prêt : http://127.0.0.1:$PORT/ (variables dans $BANC/env)"
}

case "${1:-}" in
    demarrer) demarrer ;;
    arreter) arreter; echo "Banc arrêté." ;;
    *) sed -n '2,17p' "$0"; exit 1 ;;
esac
