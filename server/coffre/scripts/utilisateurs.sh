#!/bin/sh
# =============================================================================
# coffre — gestion des comptes WebDAV
# À lancer en root sur coffre01, depuis /opt/sites/coffre :
#
#   ./scripts/utilisateurs.sh preparer           crée les dossiers et le fichier des comptes
#   ./scripts/utilisateurs.sh ajouter <nom>      crée le compte et son dossier
#   ./scripts/utilisateurs.sh renouveler <nom>   remplace le mot de passe WebDAV
#   ./scripts/utilisateurs.sh supprimer <nom>    retire le compte (les fichiers restent)
#   ./scripts/utilisateurs.sh lister             liste les comptes
#
# Le mot de passe WebDAV est généré ici (32 caractères aléatoires) et affiché
# UNE seule fois, pour être saisi dans les applications de l'utilisateur ;
# seule son empreinte bcrypt est conservée. Ce n'est PAS le mot de passe maître
# du coffre : celui-ci ne quitte jamais les terminaux.
# =============================================================================
set -eu
cd "$(dirname "$0")/.."

HTPASSWD=auth/htpasswd
BLOCS=auth/utilisateurs                        # un bloc <Directory> par utilisateur
RACINE="${RACINE_CONTENEUR:-/srv/keepass}"     # chemins vus par le conteneur webdav
UID_WWW=33          # www-data dans l'image officielle httpd (Debian)
GID_WWW=33
COUT_BCRYPT=8       # suffisant pour un mot de passe aléatoire de 192 bits

[ "$(id -u)" = "0" ] || { echo "À lancer en root." >&2; exit 1; }
PUBLIC_HOSTNAME=$(sed -n 's/^PUBLIC_HOSTNAME=//p' .env 2>/dev/null | head -n 1)

preparer() {
    install -d -m 750 -o root -g "$GID_WWW" auth "$BLOCS"
    [ -f "$HTPASSWD" ] || install -m 640 -o root -g "$GID_WWW" /dev/null "$HTPASSWD"
    install -d -m 750 -o "$UID_WWW" -g "$GID_WWW" data data/dav data/versions data/davlock
}

# Rechargement sans coupure d'Apache (SIGUSR1), pour prendre en compte les blocs.
recharger() {
    if [ -n "${HTTPD_RELOAD_CMD:-}" ]; then
        sh -c "$HTTPD_RELOAD_CMD" || true
    else
        docker compose kill -s USR1 webdav >/dev/null 2>&1 || true
    fi
}

ecrire_bloc() {
    tmp=$(mktemp "$BLOCS/.$1.XXXXXX")
    cat > "$tmp" <<EOF
# Généré par scripts/utilisateurs.sh — compte « $1 »
<Directory "$RACINE/dav/$1">
    # Pas de sous-dossier : l'historique ne suit que les coffres à la racine du dossier
    <RequireAll>
        Require user $1
        Require not method MKCOL
    </RequireAll>
</Directory>
<Directory "$RACINE/versions/$1">
    <RequireAll>
        Require user $1
        Require method GET HEAD OPTIONS PROPFIND
    </RequireAll>
</Directory>
EOF
    chown root:"$GID_WWW" "$tmp"
    chmod 640 "$tmp"
    mv "$tmp" "$BLOCS/$1.conf"
}

valider() {
    printf '%s' "$1" | grep -Eq '^[a-z0-9][a-z0-9-]{1,30}$' || {
        echo "Nom invalide : minuscules, chiffres et tirets, 2 à 31 caractères." >&2
        exit 1
    }
}

existe() { grep -q "^$1:" "$HTPASSWD"; }

# Empreinte bcrypt, calculée avec le htpasswd de l'image officielle
# (HTPASSWD_BIN permet d'utiliser un htpasswd local, par exemple pour les tests).
empreinte() {
    if [ -n "${HTPASSWD_BIN:-}" ]; then
        "$HTPASSWD_BIN" -i -n -B -C "$COUT_BCRYPT" "$1"
    else
        docker compose run --rm --no-deps -T --entrypoint htpasswd webdav -i -n -B -C "$COUT_BCRYPT" "$1"
    fi
}

generer() { head -c 24 /dev/urandom | base64 | tr '+/' '-_'; }

retirer() {
    tmp=$(mktemp "$HTPASSWD.XXXXXX")
    grep -v "^$1:" "$HTPASSWD" > "$tmp" || true
    chown root:"$GID_WWW" "$tmp"
    chmod 640 "$tmp"
    mv "$tmp" "$HTPASSWD"
}

enregistrer() {
    mdp=$(generer)
    ligne=$(printf '%s\n' "$mdp" | empreinte "$1" | grep -E "^$1:")
    [ -n "$ligne" ] || { echo "Échec du calcul de l'empreinte." >&2; exit 1; }
    printf '%s\n' "$ligne" >> "$HTPASSWD"
    cat <<EOF
Compte WebDAV « $1 » prêt.
  Adresse      : https://${PUBLIC_HOSTNAME:-<nom public>}/dav/$1/
  Identifiant  : $1
  Mot de passe : $mdp
Saisissez-le maintenant dans les applications de l'utilisateur : il ne sera plus affiché.
EOF
}

commande="${1:-}"
case "$commande" in
    preparer)
        preparer
        echo "Dossiers et fichier des comptes prêts."
        ;;
    ajouter)
        nom="${2:?nom manquant}"; valider "$nom"; preparer
        existe "$nom" && { echo "Le compte $nom existe déjà." >&2; exit 1; }
        install -d -m 750 -o "$UID_WWW" -g "$GID_WWW" "data/dav/$nom"
        ecrire_bloc "$nom"
        enregistrer "$nom"
        recharger
        ;;
    renouveler)
        nom="${2:?nom manquant}"; valider "$nom"
        existe "$nom" || { echo "Compte $nom inconnu." >&2; exit 1; }
        retirer "$nom"
        enregistrer "$nom"
        ;;
    supprimer)
        nom="${2:?nom manquant}"; valider "$nom"
        existe "$nom" || { echo "Compte $nom inconnu." >&2; exit 1; }
        retirer "$nom"
        rm -f "$BLOCS/$nom.conf"
        recharger
        echo "Compte $nom supprimé. Ses fichiers restent dans data/dav/$nom et data/versions/$nom (à effacer après 30 jours)."
        ;;
    lister)
        cut -d: -f1 "$HTPASSWD"
        ;;
    *)
        sed -n '4,10p' "$0"
        exit 1
        ;;
esac
