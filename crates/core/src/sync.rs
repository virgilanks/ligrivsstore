//! Échanges avec le serveur « coffre » (WebDAV).
//!
//! Le serveur reste aveugle : il ne stocke que le fichier chiffré. Les deux
//! seules opérations utiles sont :
//! - le téléchargement conditionnel (`GET` avec `If-None-Match`) ;
//! - l'envoi conditionnel (`PUT` avec `If-Match`, ou `If-None-Match: *` pour
//!   une création), refusé par le serveur (412) si un autre terminal a écrit
//!   entre-temps.
//!
//! La boucle complète (téléchargement, fusion, enregistrement, envoi) est dans
//! [`crate::local::LocalVault::sync`]. Le trait [`Transport`] permet de la
//! tester sans réseau.

use std::path::Path;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::error::Result;
use crate::storage;
use crate::vault::MergeReport;

/// Taille maximale d'un coffre téléchargé (le serveur refuse au-delà de 50 Mo).
pub const MAX_DOWNLOAD_BYTES: u64 = 64 * 1024 * 1024;

/// Erreur de synchronisation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SyncError {
    /// Adresse du serveur invalide.
    #[error("adresse du serveur invalide : {0}")]
    InvalidUrl(String),
    /// Adresse en `http://` vers une autre machine que la machine locale.
    #[error(
        "connexion non chiffrée refusée : utilisez https:// (http:// n'est admis que vers la machine locale, pour les tests)"
    )]
    InsecureUrl,
    /// Identifiants WebDAV refusés.
    #[error("identifiants WebDAV refusés par le serveur (401)")]
    Unauthorized,
    /// Accès refusé à cet emplacement.
    #[error("accès refusé par le serveur (403)")]
    Forbidden,
    /// Fichier verrouillé par un autre client WebDAV.
    #[error("coffre verrouillé sur le serveur par un autre client (423)")]
    Locked,
    /// Fichier trop volumineux pour le serveur.
    #[error("coffre trop volumineux pour le serveur (413)")]
    TooLarge,
    /// Réponse inattendue.
    #[error("réponse inattendue du serveur : code {0}")]
    UnexpectedStatus(u16),
    /// Le serveur ne fournit pas d'ETag : aucun envoi sûr n'est possible.
    #[error("le serveur ne fournit pas d'ETag : synchronisation sûre impossible")]
    MissingEtag,
    /// Serveur injoignable ou échange interrompu.
    #[error("serveur injoignable ou échange interrompu : {0}")]
    Network(String),
    /// Aucun coffre sur le serveur.
    #[error("aucun coffre à cette adresse sur le serveur")]
    RemoteMissing,
    /// Le coffre du serveur ne s'ouvre pas avec la clé locale.
    #[error(
        "le coffre du serveur ne s'ouvre pas avec la clé de ce terminal (phrase de passe changée sur un autre terminal ?) ; rien n'a été envoyé"
    )]
    RemoteWrongKey,
    /// Le coffre du serveur est illisible.
    #[error("le coffre du serveur est illisible ; rien n'a été envoyé : {0}")]
    RemoteUnreadable(String),
    /// Trop de conflits successifs.
    #[error("trop d'écritures concurrentes sur le serveur : réessayez dans un instant")]
    TooManyConflicts,
    /// Le serveur annonce sans cesse une version en cours d'écriture.
    #[error("le coffre du serveur est en cours d'écriture : réessayez dans un instant")]
    UnstableEtag,
}

/// Étiquette de version (ETag) renvoyée par le serveur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ETag(String);

impl ETag {
    /// Lit la valeur d'un en-tête `ETag`.
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        let opaque = value.strip_prefix("W/").unwrap_or(value);
        let valid = opaque.len() >= 2
            && opaque.starts_with('"')
            && opaque.ends_with('"')
            && opaque
                .get(1..opaque.len().saturating_sub(1))
                .is_some_and(|inner| !inner.contains('"'));
        valid.then(|| Self(value.to_owned()))
    }

    /// Vrai pour une étiquette « faible » (`W/…`) : Apache en renvoie pendant
    /// la seconde qui suit une écriture, et le serveur la refuse toujours dans
    /// un `If-Match`.
    pub fn is_weak(&self) -> bool {
        self.0.starts_with("W/")
    }

    /// Valeur brute, à renvoyer telle quelle au serveur.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Résultat d'un téléchargement.
#[derive(Debug)]
pub enum Fetch {
    /// Le coffre n'a pas changé depuis l'étiquette fournie.
    NotModified,
    /// Aucun coffre à cette adresse.
    NotFound,
    /// Contenu et étiquette du coffre.
    Found {
        /// Contenu chiffré.
        body: Vec<u8>,
        /// Étiquette de version.
        etag: Option<ETag>,
    },
}

/// Condition posée à un envoi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Precondition {
    /// Remplacer seulement si le serveur détient encore cette version.
    IfMatch(String),
    /// Créer seulement si aucun fichier n'existe.
    IfNoneMatchAny,
}

/// Résultat d'un envoi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreOutcome {
    /// Le serveur a enregistré le fichier.
    Stored,
    /// La condition n'est plus remplie : un autre terminal a écrit entre-temps.
    PreconditionFailed,
}

/// Accès au coffre distant.
pub trait Transport {
    /// Télécharge le coffre, sauf s'il porte encore l'étiquette `if_none_match`.
    fn fetch(&self, if_none_match: Option<&str>) -> Result<Fetch, SyncError>;

    /// Envoie le coffre sous condition.
    fn store(&self, body: &[u8], precondition: &Precondition) -> Result<StoreOutcome, SyncError>;
}

/// Réglages de la boucle de synchronisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncOptions {
    /// Nombre maximal de tentatives (chaque conflit en consomme une).
    pub max_attempts: u32,
    /// Attente avant de relire un coffre dont l'étiquette est faible.
    pub weak_etag_wait: Duration,
    /// Nombre maximal de relectures pour étiquette faible.
    pub max_weak_waits: u32,
}

impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            weak_etag_wait: Duration::from_millis(1_100),
            max_weak_waits: 3,
        }
    }
}

/// Bilan d'une synchronisation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Le coffre du serveur a été téléchargé.
    pub downloaded: bool,
    /// Bilan cumulé des fusions.
    pub merge: MergeReport,
    /// Le coffre local a été envoyé.
    pub uploaded: bool,
    /// Envois refusés pour conflit (412), puis repris.
    pub conflicts: u32,
    /// Relectures dues à une étiquette faible.
    pub weak_waits: u32,
}

/// État de synchronisation d'un coffre local, enregistré à côté du coffre.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncState {
    /// Étiquette (forte) de la dernière version connue du serveur.
    pub remote_etag: Option<String>,
    /// Modifications locales pas encore envoyées.
    pub local_dirty: bool,
    /// Empreinte SHA-256 du dernier envoi, pour reconnaître sa propre version.
    pub last_uploaded_sha256: Option<String>,
    /// Date de la dernière synchronisation réussie (UTC, ISO 8601).
    pub last_sync_utc: Option<String>,
}

impl SyncState {
    /// État d'un coffre dont on ne sait rien : il sera fusionné avec le serveur
    /// puis envoyé.
    pub fn unknown() -> Self {
        Self {
            local_dirty: true,
            ..Self::default()
        }
    }

    /// Lit l'état ; s'il est absent ou illisible, renvoie [`SyncState::unknown`].
    pub fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_else(Self::unknown)
    }

    /// Enregistre l'état de façon atomique.
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| crate::Error::Save(format!("état de synchronisation : {e}")))?;
        storage::replace_file(path, &json)
    }
}

/// Accès WebDAV au serveur « coffre ».
pub struct WebDavTransport {
    agent: ureq::Agent,
    url: String,
    authorization: Zeroizing<String>,
}

impl std::fmt::Debug for WebDavTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebDavTransport")
            .field("url", &self.url)
            .field("authorization", &"<masquée>")
            .finish()
    }
}

impl WebDavTransport {
    /// Prépare l'accès au fichier `url` (par exemple
    /// `https://coffre.ligrivs.com/dav/hermann/coffre.kdbx`).
    ///
    /// `https://` est obligatoire ; `http://` n'est admis que vers la machine
    /// locale (bancs de test). Les identifiants ne doivent pas figurer dans
    /// l'adresse.
    pub fn new(url: &str, username: &str, password: &str) -> Result<Self, SyncError> {
        let parsed = Url::parse(url).map_err(|e| SyncError::InvalidUrl(e.to_string()))?;
        match parsed.scheme() {
            "https" => {}
            "http" if is_loopback(&parsed) => {}
            "http" => return Err(SyncError::InsecureUrl),
            other => return Err(SyncError::InvalidUrl(format!("protocole {other}"))),
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(SyncError::InvalidUrl(
                "les identifiants ne doivent pas figurer dans l'adresse".into(),
            ));
        }
        if parsed.path().ends_with('/') || parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(SyncError::InvalidUrl(
                "l'adresse doit désigner le fichier du coffre (…/coffre.kdbx)".into(),
            ));
        }
        if username.is_empty() || username.contains(':') {
            return Err(SyncError::InvalidUrl("identifiant WebDAV invalide".into()));
        }
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_connect(Some(Duration::from_secs(15)))
            .timeout_global(Some(Duration::from_secs(120)))
            .user_agent(concat!("ligrivsstore/", env!("CARGO_PKG_VERSION")))
            .build();
        let credentials = Zeroizing::new(format!("{username}:{password}"));
        let token = Zeroizing::new(STANDARD.encode(credentials.as_bytes()));
        Ok(Self {
            agent: ureq::Agent::new_with_config(config),
            url: parsed.to_string(),
            authorization: Zeroizing::new(format!("Basic {}", token.as_str())),
        })
    }
}

impl Transport for WebDavTransport {
    fn fetch(&self, if_none_match: Option<&str>) -> Result<Fetch, SyncError> {
        let mut request = self
            .agent
            .get(&self.url)
            .header("Authorization", self.authorization.as_str())
            .header("Cache-Control", "no-cache");
        if let Some(etag) = if_none_match {
            request = request.header("If-None-Match", etag);
        }
        let mut response = request.call().map_err(network)?;
        match response.status().as_u16() {
            200 => {
                let etag = response
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .and_then(ETag::parse);
                let body = response
                    .body_mut()
                    .with_config()
                    .limit(MAX_DOWNLOAD_BYTES)
                    .read_to_vec()
                    .map_err(network)?;
                Ok(Fetch::Found { body, etag })
            }
            304 => Ok(Fetch::NotModified),
            404 => Ok(Fetch::NotFound),
            status => Err(status_error(status)),
        }
    }

    fn store(&self, body: &[u8], precondition: &Precondition) -> Result<StoreOutcome, SyncError> {
        let request = self
            .agent
            .put(&self.url)
            .header("Authorization", self.authorization.as_str())
            .header("Content-Type", "application/octet-stream");
        let request = match precondition {
            Precondition::IfMatch(etag) => request.header("If-Match", etag.as_str()),
            Precondition::IfNoneMatchAny => request.header("If-None-Match", "*"),
        };
        let response = request.send(body).map_err(network)?;
        match response.status().as_u16() {
            200 | 201 | 204 => Ok(StoreOutcome::Stored),
            412 => Ok(StoreOutcome::PreconditionFailed),
            status => Err(status_error(status)),
        }
    }
}

fn status_error(status: u16) -> SyncError {
    match status {
        401 => SyncError::Unauthorized,
        403 => SyncError::Forbidden,
        413 => SyncError::TooLarge,
        423 => SyncError::Locked,
        other => SyncError::UnexpectedStatus(other),
    }
}

fn network(error: ureq::Error) -> SyncError {
    SyncError::Network(error.to_string())
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etags_are_parsed_strictly() {
        let strong = ETag::parse("\"1f-63e2a\"").unwrap();
        assert!(!strong.is_weak());
        let weak = ETag::parse("W/\"1f-63e2a\"").unwrap();
        assert!(weak.is_weak());
        assert_eq!(weak.as_str(), "W/\"1f-63e2a\"");
        assert!(ETag::parse("sans-guillemets").is_none());
        assert!(ETag::parse("\"a\"b\"").is_none());
        assert!(ETag::parse("\"").is_none());
    }

    #[test]
    fn plain_http_is_refused_except_locally() {
        assert!(matches!(
            WebDavTransport::new("http://coffre.ligrivs.com/dav/h/coffre.kdbx", "h", "x"),
            Err(SyncError::InsecureUrl)
        ));
        assert!(WebDavTransport::new("http://127.0.0.1:18081/dav/h/coffre.kdbx", "h", "x").is_ok());
        assert!(WebDavTransport::new("http://[::1]:18081/dav/h/coffre.kdbx", "h", "x").is_ok());
        assert!(
            WebDavTransport::new("https://coffre.ligrivs.com/dav/h/coffre.kdbx", "h", "x").is_ok()
        );
    }

    #[test]
    fn credentials_and_folders_are_refused_in_urls() {
        for url in [
            "https://h:secret@coffre.ligrivs.com/dav/h/coffre.kdbx",
            "https://coffre.ligrivs.com/dav/h/",
            "https://coffre.ligrivs.com/dav/h/coffre.kdbx?x=1",
            "ftp://coffre.ligrivs.com/dav/h/coffre.kdbx",
        ] {
            assert!(
                matches!(
                    WebDavTransport::new(url, "h", "x"),
                    Err(SyncError::InvalidUrl(_))
                ),
                "{url}"
            );
        }
    }

    #[test]
    fn debug_hides_credentials() {
        let transport = WebDavTransport::new(
            "https://coffre.ligrivs.com/dav/h/coffre.kdbx",
            "h",
            "secret",
        )
        .unwrap();
        let shown = format!("{transport:?}");
        assert!(!shown.contains("secret"));
        assert!(!shown.contains(&STANDARD.encode("h:secret")));
    }

    #[test]
    fn missing_or_corrupt_state_means_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("etat.json");
        assert_eq!(SyncState::load(&path), SyncState::unknown());
        std::fs::write(&path, b"{pas du json").unwrap();
        assert_eq!(SyncState::load(&path), SyncState::unknown());
        let state = SyncState {
            remote_etag: Some("\"abc\"".into()),
            local_dirty: false,
            last_uploaded_sha256: None,
            last_sync_utc: Some("2026-11-11T10:00:00Z".into()),
        };
        state.save(&path).unwrap();
        assert_eq!(SyncState::load(&path), state);
    }
}
