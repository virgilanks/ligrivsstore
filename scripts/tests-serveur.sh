#!/usr/bin/env bash
# =============================================================================
# Tests du serveur « coffre » (configuration de server/coffre) sur le banc local.
# Les requêtes des clients passent par le relais HTTPS, comme en service ; seuls
# les contrôles internes (santé vue de Docker, adresse réelle relayée, en-tête
# Server, TRACE) visent Apache directement.
#
#   sudo scripts/banc-webdav.sh demarrer
#   sudo scripts/tests-serveur.sh
#
# Deux comptes de test (alice, bob) sont créés puis supprimés.
# =============================================================================
set -uo pipefail

BANC="${LGS_BANC_DIR:-/tmp/lgs-banc-webdav}"
[ "$(id -u)" = "0" ] || { echo "À lancer en root (sudo)." >&2; exit 1; }
[ -f "$BANC/env" ] || { echo "Banc absent : lancer d'abord sudo scripts/banc-webdav.sh demarrer" >&2; exit 1; }
set -a; . "$BANC/env"; set +a
URL="$LGS_BANC_RELAIS"        # https://127.0.0.1:18443, par le relais
DIRECT="$LGS_BANC_ARRIERE"    # http://127.0.0.1:18081, Apache seul
PORT_DIRECT="${DIRECT##*:}"
CA=(--cacert "$LGS_TEST_WEBDAV_CA")
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

reussis=0; echecs=0
ok()     { echo "RÉUSSI  $1"; reussis=$((reussis + 1)); }
ko()     { echo "ÉCHEC   $1  (obtenu : $2)"; echecs=$((echecs + 1)); }
check()  { if [ "$2" = "$3" ]; then ok "$1"; else ko "$1 [attendu $2]" "$3"; fi; }
code()   { curl -s "${CA[@]}" -o /dev/null -w '%{http_code}' "$@"; }
denied() { case "$2" in 401|403) ok "$1 (refusé : $2)" ;; *) ko "$1 [attendu 401 ou 403]" "$2" ;; esac; }

# --- Comptes, par le script livré ------------------------------------------------
cd "$BANC/site"
export HTPASSWD_BIN=/usr/bin/htpasswd RACINE_CONTENEUR="$BANC/site/data"
export HTTPD_RELOAD_CMD="kill -USR1 \$(cat $BANC/run/httpd.pid) 2>/dev/null; sleep 1"
for nom in alice bob; do
    sh scripts/utilisateurs.sh supprimer "$nom" >/dev/null 2>&1 || true
    rm -rf "data/dav/$nom" "data/versions/$nom"
done
pw_a=$(sh scripts/utilisateurs.sh ajouter alice | sed -n 's/.*Mot de passe : //p')
pw_b=$(sh scripts/utilisateurs.sh ajouter bob | sed -n 's/.*Mot de passe : //p')
check "script : mot de passe de 32 caractères" 32 "${#pw_a}"
sh scripts/utilisateurs.sh ajouter alice >/dev/null 2>&1; check "script : refus d'un doublon" 1 "$?"
sh scripts/utilisateurs.sh ajouter 'Eve!' >/dev/null 2>&1; check "script : refus d'un nom invalide" 1 "$?"
check "script : droits du fichier des comptes" "640 root www-data" "$(stat -c '%a %U %G' auth/htpasswd)"
check "script : propriétaire du dossier d'alice" "750 www-data www-data" "$(stat -c '%a %U %G' data/dav/alice)"
check "script : empreinte bcrypt de coût 8" 1 "$(grep -c '^alice:\$2y\$08\$' auth/htpasswd)"
check "script : bloc de droits d'alice généré" 2 "$(grep -c 'Require user alice' auth/utilisateurs/alice.conf)"
check "script : sous-dossiers interdits dans le bloc (MKCOL)" 1 "$(grep -c 'Require not method MKCOL' auth/utilisateurs/alice.conf)"
A=(-u "alice:$pw_a"); B=(-u "bob:$pw_b")

# --- Santé et en-têtes -------------------------------------------------------------
check "santé par le relais : 200" 200 "$(code "$URL/healthz")"
check "santé : corps « ok »" ok "$(curl -s "${CA[@]}" "$URL/healthz")"
hdr=$(curl -s "${CA[@]}" -D - -o /dev/null "$URL/healthz" | tr -d '\r')
check "santé : type text/plain" 1 "$(grep -ci '^content-type: text/plain' <<<"$hdr")"
check "en-tête Cache-Control: no-store" 1 "$(grep -ci '^cache-control: no-store' <<<"$hdr")"
check "en-tête X-Content-Type-Options: nosniff" 1 "$(grep -ci '^x-content-type-options: nosniff' <<<"$hdr")"
check "en-tête Server sans version (Apache seul)" "Server: Apache" "$(curl -s -D - -o /dev/null "$DIRECT/healthz" | tr -d '\r' | grep -i '^server:')"
check "TRACE refusé (Apache seul)" 405 "$(curl -s -o /dev/null -w '%{http_code}' -X TRACE "$DIRECT/healthz")"
check "racine du site refusée" 403 "$(code "$URL/")"
check "contrôle de santé de Docker (bash /dev/tcp)" 0 "$(bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT_DIRECT && printf 'GET /healthz HTTP/1.0\\r\\n\\r\\n' >&3 && grep -q '^ok' <&3"; echo $?)"

# --- Authentification et cloisonnement, par HTTPS ----------------------------------
check "PROPFIND /dav/ sans compte" 403 "$(code -X PROPFIND -H 'Depth: 1' "$URL/dav/")"
check "PROPFIND /dav/ (liste des utilisateurs) refusé même authentifié" 403 "$(code "${A[@]}" -X PROPFIND -H 'Depth: 1' "$URL/dav/")"
check "PROPFIND /dav/alice/ sans compte" 401 "$(code -X PROPFIND -H 'Depth: 1' "$URL/dav/alice/")"
check "OPTIONS /dav/alice/ sans compte" 401 "$(code -X OPTIONS "$URL/dav/alice/")"
check "mauvais mot de passe" 401 "$(code -u alice:mauvais -X PROPFIND -H 'Depth: 1' "$URL/dav/alice/")"
check "PROPFIND /dav/alice/ par alice" 207 "$(code "${A[@]}" -X PROPFIND -H 'Depth: 1' "$URL/dav/alice/")"
head -c 300000 /dev/urandom > "$T/coffre-v1.kdbx"
check "PUT création par alice" 201 "$(code "${A[@]}" -T "$T/coffre-v1.kdbx" "$URL/dav/alice/coffre.kdbx")"
check "PUT remplacement par alice" 204 "$(code "${A[@]}" -T "$T/coffre-v1.kdbx" "$URL/dav/alice/coffre.kdbx")"
curl -s "${CA[@]}" "${A[@]}" -o "$T/lu.kdbx" "$URL/dav/alice/coffre.kdbx"
check "GET par alice : contenu identique" 0 "$(cmp -s "$T/coffre-v1.kdbx" "$T/lu.kdbx"; echo $?)"
check "GET : ETag présent" 1 "$(curl -s "${CA[@]}" "${A[@]}" -D - -o /dev/null "$URL/dav/alice/coffre.kdbx" | grep -ci '^etag:')"
denied "GET du coffre d'alice par bob" "$(code "${B[@]}" "$URL/dav/alice/coffre.kdbx")"
denied "PUT dans le dossier d'alice par bob" "$(code "${B[@]}" -T "$T/coffre-v1.kdbx" "$URL/dav/alice/intrus.kdbx")"
denied "PROPFIND /dav/bob/ par alice" "$(code "${A[@]}" -X PROPFIND -H 'Depth: 1' "$URL/dav/bob/")"
denied "MKCOL d'un dossier étranger par alice" "$(code "${A[@]}" -X MKCOL "$URL/dav/eve/")"
check "MKCOL d'un sous-dossier dans son dossier : refusé (pas de sous-dossier)" 403 "$(code "${A[@]}" -X MKCOL "$URL/dav/alice/sous-dossier/")"
denied "MOVE vers le dossier de bob par alice" "$(code "${A[@]}" -X MOVE -H "Destination: $URL/dav/bob/vol.kdbx" "$URL/dav/alice/coffre.kdbx")"
check "MOVE refusé : le fichier reste chez alice, rien chez bob" "1 0" "$(ls data/dav/alice | grep -c '^coffre.kdbx$') $(ls data/dav/bob | wc -l)"
denied "COPY vers le dossier de bob par alice" "$(code "${A[@]}" -X COPY -H "Destination: $URL/dav/bob/copie.kdbx" "$URL/dav/alice/coffre.kdbx")"
denied "MOVE vers l'historique par alice" "$(code "${A[@]}" -X MOVE -H "Destination: $URL/versions/alice/x.kdbx" "$URL/dav/alice/coffre.kdbx")"
copie=$(curl -s "${CA[@]}" "${A[@]}" -X COPY -H "Destination: $URL/dav/alice/copie.kdbx" -D - -o /dev/null "$URL/dav/alice/coffre.kdbx" | tr -d '\r')
check "COPY dans son dossier, par HTTPS" 201 "$(sed -n '1s/^HTTP\/[0-9.]* \([0-9]*\).*/\1/p' <<<"$copie")"
check "COPY : en-tête Location en https" 1 "$(grep -ci '^location: https://' <<<"$copie")"
check "MOVE dans son dossier, par HTTPS" 201 "$(code "${A[@]}" -X MOVE -H "Destination: $URL/dav/alice/copie2.kdbx" "$URL/dav/alice/copie.kdbx")"
check "DELETE dans son dossier" 204 "$(code "${A[@]}" -X DELETE "$URL/dav/alice/copie2.kdbx")"
lockbody='<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner>test</D:owner></D:lockinfo>'
lockhdr=$(curl -s "${CA[@]}" "${A[@]}" -X LOCK -H 'Timeout: Second-60' -H 'Content-Type: application/xml' --data "$lockbody" -D - -o /dev/null "$URL/dav/alice/coffre.kdbx" | tr -d '\r')
check "LOCK par alice" 1 "$(grep -c '^HTTP/1.1 200' <<<"$lockhdr")"
token=$(sed -n 's/^Lock-Token: //Ip' <<<"$lockhdr")
check "UNLOCK par alice" 204 "$(code "${A[@]}" -X UNLOCK -H "Lock-Token: $token" "$URL/dav/alice/coffre.kdbx")"
denied "chemin détourné (../bob)" "$(code "${A[@]}" --path-as-is "$URL/dav/alice/../bob/")"
check "majuscules (ALICE) refusées" 403 "$(code "${A[@]}" -X PROPFIND -H 'Depth: 1' "$URL/dav/ALICE/")"
head -c 60000000 /dev/zero > "$T/gros.bin"
check "envoi de 60 Mo refusé (limite de 50 Mo)" 413 "$(code "${A[@]}" -T "$T/gros.bin" "$URL/dav/alice/gros.bin")"

# --- Historique ----------------------------------------------------------------------
H() { runuser -u www-data -- env RUN_ONCE=1 DAV_DIR="$BANC/site/data/dav" VERSIONS_DIR="$BANC/site/data/versions" RETENTION_DAYS="${1:-30}" busybox sh "$BANC/site/scripts/historique.sh"; }
H >/dev/null
check "historique : première copie" 1 "$(ls data/versions/alice/coffre.kdbx | wc -l)"
H >/dev/null
check "historique : pas de copie sans changement" 1 "$(ls data/versions/alice/coffre.kdbx | wc -l)"
sleep 1; head -c 300000 /dev/urandom > "$T/coffre-v2.kdbx"
curl -s "${CA[@]}" "${A[@]}" -T "$T/coffre-v2.kdbx" -o /dev/null "$URL/dav/alice/coffre.kdbx"
curl -s "${CA[@]}" "${A[@]}" -T "$T/coffre-v2.kdbx" -o /dev/null "$URL/dav/alice/.coffre.kdbx.tmp"
H >/dev/null
check "historique : nouvelle copie après modification" 2 "$(ls data/versions/alice/coffre.kdbx | wc -l)"
check "historique : fichier temporaire ignoré" 0 "$(ls data/versions/alice | grep -c 'tmp')"
v1=$(ls data/versions/alice/coffre.kdbx | sort | head -n 1)
check "PROPFIND /versions/alice/ par alice" 207 "$(code "${A[@]}" -X PROPFIND -H 'Depth: 1' "$URL/versions/alice/")"
curl -s "${CA[@]}" "${A[@]}" -o "$T/v1.kdbx" "$URL/versions/alice/coffre.kdbx/$v1"
check "GET d'une version : contenu de la v1" 0 "$(cmp -s "$T/coffre-v1.kdbx" "$T/v1.kdbx"; echo $?)"
denied "PUT dans l'historique" "$(code "${A[@]}" -T "$T/coffre-v1.kdbx" "$URL/versions/alice/coffre.kdbx/faux.kdbx")"
denied "DELETE dans l'historique" "$(code "${A[@]}" -X DELETE "$URL/versions/alice/coffre.kdbx/$v1")"
denied "historique d'alice lu par bob" "$(code "${B[@]}" "$URL/versions/alice/coffre.kdbx/$v1")"
check "liste /versions/ refusée" 403 "$(code "${A[@]}" -X PROPFIND -H 'Depth: 1' "$URL/versions/")"
for f in data/versions/alice/coffre.kdbx/*; do touch -d '40 days ago' "$f"; done
H 30 >/dev/null
check "purge : copies de plus de 30 jours supprimées, la plus récente gardée" 1 "$(ls data/versions/alice/coffre.kdbx | wc -l)"

# --- Journaux ------------------------------------------------------------------------
curl -s -o /dev/null -H 'X-Forwarded-For: 203.0.113.7' "$DIRECT/healthz"
check "journal : adresse du client relayée par edge01" 1 "$(grep -c '^203.0.113.7 ' "$BANC/run/access.log")"
check "journal : aucun mot de passe journalisé" 0 "$(cat "$BANC/run/access.log" "$BANC/run/error.log" | grep -c -- "$pw_a")"

# --- Renouvellement et suppression de compte ----------------------------------------
pw_r=$(sh scripts/utilisateurs.sh renouveler alice | sed -n 's/.*Mot de passe : //p')
check "renouvellement : ancien mot de passe refusé aussitôt" 401 "$(code -u "alice:$pw_a" -X PROPFIND -H 'Depth: 1' "$URL/dav/alice/")"
check "renouvellement : nouveau mot de passe accepté" 207 "$(code -u "alice:$pw_r" -X PROPFIND -H 'Depth: 1' "$URL/dav/alice/")"
sh scripts/utilisateurs.sh supprimer bob >/dev/null
check "suppression : bloc de bob retiré" 0 "$(ls auth/utilisateurs | grep -c '^bob.conf$')"
denied "suppression : bob ne se connecte plus" "$(code "${B[@]}" -X PROPFIND -H 'Depth: 1' "$URL/dav/bob/")"
check "liste des comptes : alice présente, bob absent" "1 0" "$(sh scripts/utilisateurs.sh lister | grep -c '^alice$') $(sh scripts/utilisateurs.sh lister | grep -c '^bob$')"

# --- Nettoyage -------------------------------------------------------------------------
sh scripts/utilisateurs.sh supprimer alice >/dev/null 2>&1 || true
rm -rf data/dav/alice data/dav/bob data/versions/alice data/versions/bob
echo "--- erreurs du serveur ---"
grep -v -iE 'AH00558|resuming normal operations|caught SIGTERM|caught SIGWINCH|AH00493' "$BANC/run/error.log" | tail -5
echo
echo "RÉSULTAT : $reussis réussis, $echecs échoués"
[ "$echecs" -eq 0 ]
