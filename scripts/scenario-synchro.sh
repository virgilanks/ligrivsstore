#!/usr/bin/env bash
# =============================================================================
# Scénario de recette de bout en bout, avec l'outil lgs et KeePassXC :
# deux terminaux, modifications concurrentes, fusion, lecture par KeePassXC,
# opérations WebDAV par HTTPS (COPY, MOVE, MKCOL) et refus attendus.
#
#   cargo build -p ligrivsstore-cli
#   sudo scripts/banc-webdav.sh demarrer
#   set -a; . /tmp/lgs-banc-webdav/env; set +a
#   scripts/scenario-synchro.sh
#
# Contre le serveur déployé : définir LGS_TEST_WEBDAV_URL (dossier de
# l'utilisateur, https://…/dav/<compte>/), LGS_TEST_WEBDAV_USER et
# LGS_TEST_WEBDAV_PASSWORD (saisi au clavier, jamais écrit dans un fichier) ;
# ne pas définir LGS_TEST_WEBDAV_CA. Les refus d'identifiants volontaires ne
# sont alors pas joués : CrowdSec bannit l'adresse après cinq échecs en rafale.
# =============================================================================
set -uo pipefail

RACINE_DEPOT="$(cd "$(dirname "$0")/.." && pwd)"
# Dossier des fichiers compilés, tel que cargo le voit (CARGO_TARGET_DIR,
# configuration de cargo), sinon celui du dépôt.
CIBLE="$(cd "$RACINE_DEPOT" && cargo metadata --format-version 1 --no-deps 2>/dev/null \
    | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')"
LGS="${LGS_BIN:-${CIBLE:-$RACINE_DEPOT/target}/debug/lgs}"
[ -x "$LGS" ] || { echo "Outil lgs introuvable ($LGS) : lancer d'abord cargo build -p ligrivsstore-cli" >&2; exit 1; }
: "${LGS_TEST_WEBDAV_URL:?définir LGS_TEST_WEBDAV_URL, voir les instructions en tête du script}"
: "${LGS_TEST_WEBDAV_USER:?définir LGS_TEST_WEBDAV_USER}"
: "${LGS_TEST_WEBDAV_PASSWORD:?définir LGS_TEST_WEBDAV_PASSWORD}"

TRAVAIL="$(mktemp -d)"
trap 'rm -rf "$TRAVAIL"' EXIT
cd "$TRAVAIL"

export LGS_PASSWORD="phrase de recette $(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export LGS_WEBDAV_PASSWORD="$LGS_TEST_WEBDAV_PASSWORD"
DOSSIER="${LGS_TEST_WEBDAV_URL%/}"
URL="$DOSSIER/recette-$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n').kdbx"
SERVEUR=(--url "$URL" --user "$LGS_TEST_WEBDAV_USER")
CURL=(curl -s -u "$LGS_TEST_WEBDAV_USER:$LGS_WEBDAV_PASSWORD")
if [ -n "${LGS_TEST_WEBDAV_CA:-}" ]; then
    SERVEUR+=(--ca-file "$LGS_TEST_WEBDAV_CA")
    CURL+=(--cacert "$LGS_TEST_WEBDAV_CA")
fi
case "$DOSSIER" in
    http://127.0.0.1[:/]* | https://127.0.0.1[:/]* | http://localhost[:/]* | https://localhost[:/]*) BANC_LOCAL=1 ;;
    *) BANC_LOCAL=0 ;;
esac
head -c 64 /dev/urandom > cle.keyx

reussis=0; echecs=0
verifier() {  # verifier <libellé> <motif attendu> <texte>
    if grep -q -- "$2" <<<"$3"; then
        echo "RÉUSSI  $1"; reussis=$((reussis + 1))
    else
        echo "ÉCHEC   $1 (attendu : $2)"; sed 's/^/        /' <<<"$3" | head -5; echecs=$((echecs + 1))
    fi
}

echo "== 1. Terminal A : création, entrée, envoi"
"$LGS" new a.kdbx -k cle.keyx --name "Coffre de recette" >/dev/null
LGS_ENTRY_PASSWORD="ancien-mot-de-passe" "$LGS" add a.kdbx -k cle.keyx --title Banque \
    --url https://banque.exemple.test --username hermann >/dev/null
verifier "A envoie le coffre (création conditionnelle)" "envoyé oui" "$("$LGS" sync a.kdbx -k cle.keyx "${SERVEUR[@]}" 2>&1)"

echo "== 2. Terminal B : installation depuis le serveur"
verifier "B installe le coffre" "1 entrées" "$("$LGS" clone b.kdbx -k cle.keyx "${SERVEUR[@]}" 2>&1)"

echo "== 3. Modifications concurrentes"
sleep 1.1
LGS_ENTRY_PASSWORD="nouveau-mot-de-passe-A" "$LGS" edit a.kdbx -k cle.keyx Banque --password-from-env >/dev/null
LGS_ENTRY_PASSWORD="mot-de-passe-B" "$LGS" add b.kdbx -k cle.keyx --title Messagerie \
    --url https://mail.exemple.test --username hermann >/dev/null
verifier "A envoie sa modification" "envoyé oui" "$("$LGS" sync a.kdbx -k cle.keyx "${SERVEUR[@]}" 2>&1)"
verifier "B télécharge, fusionne et envoie" "téléchargé oui, fusion [1-9].*envoyé oui" \
    "$("$LGS" sync b.kdbx -k cle.keyx "${SERVEUR[@]}" 2>&1)"
verifier "A reçoit l'ajout de B" "téléchargé oui" "$("$LGS" sync a.kdbx -k cle.keyx "${SERVEUR[@]}" 2>&1)"

echo "== 4. Résultat sur les deux terminaux"
for terminal in a b; do
    liste=$("$LGS" list "$terminal.kdbx" -k cle.keyx 2>&1)
    verifier "$terminal : entrée Banque présente" "^Banque" "$liste"
    verifier "$terminal : entrée Messagerie présente" "^Messagerie" "$liste"
    verifier "$terminal : modification de A conservée" "nouveau-mot-de-passe-A" \
        "$("$LGS" show "$terminal.kdbx" -k cle.keyx Banque --reveal 2>&1)"
done

echo "== 5. Coffre du serveur"
"${CURL[@]}" -f -o distant.kdbx "$URL"
info=$("$LGS" info distant.kdbx 2>&1)
verifier "format KDBX 4.1" "KDBX 4.1" "$info"
verifier "dérivation Argon2id 32 Mio" "Argon2id, 32 Mio" "$info"
if command -v keepassxc-cli >/dev/null; then
    xc=$(printf '%s\n' "$LGS_PASSWORD" | keepassxc-cli ls -q -k cle.keyx distant.kdbx 2>&1)
    verifier "KeePassXC lit le coffre du serveur" "Messagerie" "$xc"
    xc=$(printf '%s\n' "$LGS_PASSWORD" | keepassxc-cli show -q -s -a Password -k cle.keyx distant.kdbx Banque 2>&1)
    verifier "KeePassXC lit le mot de passe modifié par A" "nouveau-mot-de-passe-A" "$xc"
else
    echo "(keepassxc-cli absent : vérifications KeePassXC sautées)"
fi

echo "== 6. Opérations WebDAV par HTTPS (revue infra du 11 novembre 2026)"
COPIE="${URL%.kdbx}-copie.kdbx"
DEPLACE="${URL%.kdbx}-deplace.kdbx"
code_http() { "${CURL[@]}" -o /dev/null -w '%{http_code}' "$@"; }
verifier "COPY dans son dossier : 201" "^201$" "$(code_http -X COPY -H "Destination: $COPIE" "$URL")"
verifier "MOVE dans son dossier : 201" "^201$" "$(code_http -X MOVE -H "Destination: $DEPLACE" "$COPIE")"
verifier "MKCOL d'un sous-dossier : refusé (403)" "^403$" "$(code_http -X MKCOL "$DOSSIER/sous-dossier-recette/")"
code_http -X DELETE "$DEPLACE" >/dev/null

echo "== 7. Refus attendus"
verifier "coffre dans un sous-dossier : refusé par lgs" "racine du dossier" \
    "$("$LGS" sync a.kdbx -k cle.keyx --url "$DOSSIER/sous/coffre.kdbx" --user "$LGS_TEST_WEBDAV_USER" 2>&1)"
verifier "nom de fichier temporaire : refusé par lgs" "temporaire" \
    "$("$LGS" sync a.kdbx -k cle.keyx --url "$DOSSIER/coffre.kdbx.tmp" --user "$LGS_TEST_WEBDAV_USER" 2>&1)"
verifier "http:// vers une autre machine : refus" "non chiffrée" \
    "$("$LGS" sync a.kdbx -k cle.keyx --url http://coffre.exemple.test/dav/x/c.kdbx --user x 2>&1)"
verifier "sans le fichier clé : refus" "clé incorrecte" "$("$LGS" list a.kdbx 2>&1)"
if [ "$BANC_LOCAL" = 1 ]; then
    verifier "mauvais mot de passe WebDAV : refus (401)" "401" \
        "$(LGS_WEBDAV_PASSWORD=mauvais "$LGS" sync a.kdbx -k cle.keyx "${SERVEUR[@]}" 2>&1)"
    verifier "après un refus, synchronisation suspendue sans requête" "suspendue" \
        "$("$LGS" sync a.kdbx -k cle.keyx "${SERVEUR[@]}" 2>&1)"
    verifier "nouvelle saisie : synchronisation reprise" "synchronisé" \
        "$("$LGS" sync a.kdbx -k cle.keyx "${SERVEUR[@]}" --new-credentials 2>&1)"
else
    echo "(serveur déployé : refus d'identifiants volontaires sautés, CrowdSec)"
fi

code_http -X DELETE "$URL" >/dev/null
echo
echo "RÉSULTAT : $reussis réussis, $echecs échoués"
[ "$echecs" -eq 0 ]
