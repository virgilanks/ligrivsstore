#!/usr/bin/env bash
# =============================================================================
# Banc WebDAV local : le serveur « coffre » (configuration de server/coffre,
# chemins adaptés) sur Apache 2.4, derrière un relais HTTPS, comme en service :
#
#   client ──HTTPS──► relais TLS (127.0.0.1:18443) ──HTTP──► Apache « coffre » (127.0.0.1:18081)
#
# Le relais joue le rôle de Cloudflare et de Caddy : il termine le chiffrement,
# garde le nom d'hôte demandé et transmet l'adresse du visiteur seule dans
# X-Forwarded-For. Sans lui, certains défauts restent invisibles : MOVE et COPY
# échouaient (502) dès que le client parle en HTTPS (revue infra du 11 novembre 2026).
#
#   sudo scripts/banc-webdav.sh demarrer   démarre le banc et crée deux comptes
#   sudo scripts/banc-webdav.sh arreter    arrête le banc et efface ses fichiers
#
# Prérequis : Apache 2.4 (paquets apache2 et apache2-utils), openssl, curl,
# droits root. Après le démarrage, les variables des tests sont dans
# $LGS_BANC_DIR/env :
#   set -a; . /tmp/lgs-banc-webdav/env; set +a
#   cargo test -p ligrivsstore-core --test webdav
#
# L'autorité de certification et les mots de passe des comptes de test sont
# générés à chaque démarrage et n'existent que sur ce banc.
# =============================================================================
set -euo pipefail

RACINE_DEPOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="${LGS_BANC_SOURCE:-$RACINE_DEPOT/server/coffre}"
BANC="${LGS_BANC_DIR:-/tmp/lgs-banc-webdav}"
PORT="${LGS_BANC_PORT:-18081}"
PORT_TLS="${LGS_BANC_PORT_TLS:-18443}"
MODULES="${APACHE_MODULES_DIR:-/usr/lib/apache2/modules}"
APACHE="${APACHE_BIN:-/usr/sbin/apache2}"

[ "$(id -u)" = "0" ] || { echo "À lancer en root (sudo)." >&2; exit 1; }

arreter() {
    pkill -f "$APACHE -f $BANC/" 2>/dev/null || true
    sleep 0.5
    rm -rf "$BANC"
}

# Autorité de certification et certificat du relais (127.0.0.1 et localhost).
certificats() {
    local tls="$BANC/tls"
    mkdir -p "$tls"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
        -subj "/CN=Banc ligrivsstore - autorite locale" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -keyout "$tls/ca.key" -out "$tls/ca.pem" 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -subj "/CN=127.0.0.1" -keyout "$tls/serveur.key" -out "$tls/serveur.csr" 2>/dev/null
    printf '%s\n' "subjectAltName=IP:127.0.0.1,DNS:localhost" "basicConstraints=critical,CA:FALSE" \
        "keyUsage=critical,digitalSignature" "extendedKeyUsage=serverAuth" > "$tls/serveur.ext"
    openssl x509 -req -in "$tls/serveur.csr" -CA "$tls/ca.pem" -CAkey "$tls/ca.key" \
        -CAcreateserial -days 30 -extfile "$tls/serveur.ext" -out "$tls/serveur.pem" 2>/dev/null
    rm -f "$tls/ca.key" "$tls/serveur.csr" "$tls/serveur.ext" "$tls/ca.srl"
    chown root:www-data "$tls/serveur.key"
    chmod 640 "$tls/serveur.key"
    chmod 644 "$tls/ca.pem" "$tls/serveur.pem"
    chmod 755 "$tls"
}

# Relais TLS (Apache : mod_ssl et mod_proxy_http), à la place de Cloudflare et de Caddy.
relais() {
    mkdir -p "$BANC/relais"
    cat > "$BANC/relais/httpd.conf" <<EOF
ServerRoot "$BANC/relais"
Listen 127.0.0.1:$PORT_TLS
ServerName localhost
PidFile $BANC/run/relais.pid
DefaultRuntimeDir $BANC/run
LoadModule mpm_event_module $MODULES/mod_mpm_event.so
LoadModule authz_core_module $MODULES/mod_authz_core.so
LoadModule socache_shmcb_module $MODULES/mod_socache_shmcb.so
LoadModule ssl_module $MODULES/mod_ssl.so
LoadModule proxy_module $MODULES/mod_proxy.so
LoadModule proxy_http_module $MODULES/mod_proxy_http.so
LoadModule headers_module $MODULES/mod_headers.so
<IfModule !unixd_module>
    LoadModule unixd_module $MODULES/mod_unixd.so
</IfModule>
<IfModule !log_config_module>
    LoadModule log_config_module $MODULES/mod_log_config.so
</IfModule>
User www-data
Group www-data
ErrorLog $BANC/run/relais-error.log
LogLevel warn
SSLEngine on
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCertificateFile $BANC/tls/serveur.pem
SSLCertificateKeyFile $BANC/tls/serveur.key
SSLSessionCache "shmcb:$BANC/run/ssl_scache(512000)"
<Location "/">
    Require all granted
</Location>
ProxyRequests Off
# Comme Caddy : nom d'hôte du client conservé, adresse du visiteur seule dans X-Forwarded-For.
ProxyPreserveHost On
ProxyAddHeaders Off
RequestHeader set X-Forwarded-For "expr=%{REMOTE_ADDR}"
RequestHeader set X-Forwarded-Proto "https"
ProxyPass "/" "http://127.0.0.1:$PORT/"
ProxyPassReverse "/" "http://127.0.0.1:$PORT/"
EOF
    chmod -R a+rX "$BANC/relais"
}

attendre() {  # attendre <adresse> <options curl...>
    local adresse="$1"; shift
    for _ in $(seq 1 50); do
        if curl -sf "$@" "$adresse/healthz" | grep -q '^ok'; then
            return 0
        fi
        sleep 0.1
    done
    return 1
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
    certificats
    relais
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
    runuser -u www-data -- "$APACHE" -f "$BANC/relais/httpd.conf"
    if ! attendre "http://127.0.0.1:$PORT" || ! attendre "https://127.0.0.1:$PORT_TLS" --cacert "$BANC/tls/ca.pem"; then
        echo "Le banc ne répond pas ; journaux :" >&2
        cat "$BANC/run/error.log" "$BANC/run/relais-error.log" >&2 2>/dev/null || true
        exit 1
    fi

    umask 077
    cat > "$BANC/env" <<EOF
LGS_TEST_WEBDAV_URL=https://127.0.0.1:$PORT_TLS/dav/recette1/
LGS_TEST_WEBDAV_CA=$BANC/tls/ca.pem
LGS_TEST_WEBDAV_USER=recette1
LGS_TEST_WEBDAV_PASSWORD=$mdp1
LGS_TEST_WEBDAV_USER2=recette2
LGS_TEST_WEBDAV_PASSWORD2=$mdp2
LGS_BANC_DIR=$BANC
LGS_BANC_RELAIS=https://127.0.0.1:$PORT_TLS
LGS_BANC_ARRIERE=http://127.0.0.1:$PORT
EOF
    # Lisible par l'utilisateur qui a lancé sudo (les tests ne tournent pas en root).
    if [ -n "${SUDO_USER:-}" ]; then
        chown "$SUDO_USER" "$BANC/env"
    fi
    echo "Banc prêt : https://127.0.0.1:$PORT_TLS/ (relais) → http://127.0.0.1:$PORT/ (variables dans $BANC/env)"
}

case "${1:-}" in
    demarrer) demarrer ;;
    arreter) arreter; echo "Banc arrêté." ;;
    *) sed -n '2,24p' "$0"; exit 1 ;;
esac
