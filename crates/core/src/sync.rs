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
//!
//! ## Règles du serveur « coffre » (revue infra du 11 novembre 2026)
//!
//! - Le coffre est à la racine du dossier du compte : `/dav/<compte>/<coffre>.kdbx`.
//!   L'historique du serveur ne suit pas les sous-dossiers, que le serveur refuse
//!   d'ailleurs de créer.
//! - Un nom de fichier temporaire (`.tmp`, `~`, `.lock`, nom commençant par un
//!   point) n'est pas historisé : un coffre ne doit jamais en porter un.
//! - 50 Mo au plus par fichier.
//! - Chaque requête porte les identifiants (jamais de premier essai anonyme).
//!   Après un refus (401), la synchronisation automatique est suspendue :
//!   CrowdSec bannit l'adresse 4 heures après cinq échecs en rafale.

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

/// Taille maximale d'un envoi : 50 Mo, la limite du serveur « coffre »
/// (`LimitRequestBody 52428800`).
pub const MAX_UPLOAD_BYTES: u64 = 52_428_800;

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
    /// Identifiants WebDAV refusés (401).
    ///
    /// Ne jamais réessayer automatiquement : après cinq échecs en rafale,
    /// CrowdSec bannit l'adresse pendant 4 heures. [`crate::LocalVault`]
    /// suspend la synchronisation jusqu'à une nouvelle saisie.
    #[error(
        "identifiants WebDAV refusés par le serveur (401) : synchronisation suspendue jusqu'à une nouvelle saisie"
    )]
    Unauthorized,
    /// Synchronisation suspendue après un refus d'identifiants.
    #[error(
        "synchronisation suspendue depuis le {0} : identifiants WebDAV refusés ; saisissez-les de nouveau (cinq échecs en rafale font bannir l'adresse pendant 4 heures)"
    )]
    CredentialsSuspended(String),
    /// Accès refusé à cet emplacement.
    #[error("accès refusé par le serveur (403)")]
    Forbidden,
    /// Fichier verrouillé par un autre client WebDAV.
    #[error("coffre verrouillé sur le serveur par un autre client (423)")]
    Locked,
    /// Fichier trop volumineux pour le serveur (50 Mo au plus).
    #[error("coffre trop volumineux pour le serveur : 50 Mo au plus")]
    TooLarge,
    /// Certificat d'autorité illisible.
    #[error("certificat d'autorité illisible : {0}")]
    InvalidCertificate(String),
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
#[serde(default)]
pub struct SyncState {
    /// Étiquette (forte) de la dernière version connue du serveur.
    pub remote_etag: Option<String>,
    /// Modifications locales pas encore envoyées.
    pub local_dirty: bool,
    /// Empreinte SHA-256 du dernier envoi, pour reconnaître sa propre version.
    pub last_uploaded_sha256: Option<String>,
    /// Date de la dernière synchronisation réussie (UTC, ISO 8601).
    pub last_sync_utc: Option<String>,
    /// Date du dernier refus d'identifiants (UTC, ISO 8601) : tant qu'elle est
    /// présente, la synchronisation est suspendue.
    pub credentials_rejected_utc: Option<String>,
    /// Empreinte SHA-256 du dernier fichier local écrit par le noyau. À
    /// l'ouverture, elle dit si le fichier est bien le sien, et donc s'il peut
    /// être envoyé tel quel.
    pub last_written_sha256: Option<String>,
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

/// Réglages d'un accès WebDAV.
#[derive(Clone, PartialEq, Eq)]
pub struct TransportOptions {
    /// Délai d'établissement de la connexion.
    pub connect_timeout: Duration,
    /// Durée maximale d'un échange complet (envoi ou téléchargement).
    pub request_timeout: Duration,
    /// Autorité de certification seule reconnue (PEM) : banc d'essai, ou
    /// serveur doté d'une autorité privée. Sans elle, seules les autorités
    /// publiques le sont.
    pub root_ca_pem: Option<Vec<u8>>,
}

impl Default for TransportOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(15),
            request_timeout: Duration::from_secs(120),
            root_ca_pem: None,
        }
    }
}

impl std::fmt::Debug for TransportOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportOptions")
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("root_ca_pem", &self.root_ca_pem.as_ref().map(Vec::len))
            .finish()
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
        Self::with_options(url, username, password, &TransportOptions::default())
    }

    /// Comme [`WebDavTransport::new`], avec des délais et une autorité de
    /// certification choisis.
    pub fn with_options(
        url: &str,
        username: &str,
        password: &str,
        options: &TransportOptions,
    ) -> Result<Self, SyncError> {
        let roots = match &options.root_ca_pem {
            Some(pem) => {
                let certificate = ureq::tls::Certificate::from_pem(pem)
                    .map_err(|e| SyncError::InvalidCertificate(e.to_string()))?;
                Some(ureq::tls::RootCerts::new_with_certs(&[certificate]))
            }
            None => None,
        };
        Self::build(url, username, password, roots, options)
    }

    /// Comme [`WebDavTransport::new`], mais ne fait confiance qu'à l'autorité de
    /// certification fournie (PEM) : banc d'essai, ou serveur doté d'une autorité
    /// privée. Sans cette option, seules les autorités publiques sont reconnues.
    pub fn with_root_ca(
        url: &str,
        username: &str,
        password: &str,
        ca_pem: &[u8],
    ) -> Result<Self, SyncError> {
        let options = TransportOptions {
            root_ca_pem: Some(ca_pem.to_vec()),
            ..TransportOptions::default()
        };
        Self::with_options(url, username, password, &options)
    }

    fn build(
        url: &str,
        username: &str,
        password: &str,
        roots: Option<ureq::tls::RootCerts>,
        options: &TransportOptions,
    ) -> Result<Self, SyncError> {
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
        check_remote_location(&parsed, username)?;
        let mut builder = ureq::Agent::config_builder();
        if let Some(roots) = roots {
            builder = builder.tls_config(ureq::tls::TlsConfig::builder().root_certs(roots).build());
        }
        let config = builder
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_connect(Some(options.connect_timeout))
            .timeout_global(Some(options.request_timeout))
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
        if u64::try_from(body.len()).unwrap_or(u64::MAX) > MAX_UPLOAD_BYTES {
            return Err(SyncError::TooLarge);
        }
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

/// Vérifie le nom du fichier d'un coffre sur le serveur : extension `.kdbx`,
/// et jamais un nom que le serveur traite comme temporaire (non historisé).
pub fn validate_file_name(name: &str) -> Result<(), SyncError> {
    if name.is_empty() {
        return Err(SyncError::InvalidUrl(
            "l'adresse doit désigner le fichier du coffre (…/coffre.kdbx)".into(),
        ));
    }
    let lower = name.to_ascii_lowercase();
    if name.starts_with('.')
        || lower.ends_with(".tmp")
        || name.ends_with('~')
        || lower.ends_with(".lock")
    {
        return Err(SyncError::InvalidUrl(format!(
            "« {name} » est un nom de fichier temporaire, que le serveur n'historise pas"
        )));
    }
    if !lower.ends_with(".kdbx") {
        return Err(SyncError::InvalidUrl(format!(
            "« {name} » : le coffre doit porter l'extension .kdbx"
        )));
    }
    Ok(())
}

/// Vérifie l'emplacement du coffre. Sur le serveur « coffre » (chemins en
/// `/dav/`), il doit être à la racine du dossier du compte :
/// `/dav/<compte>/<coffre>.kdbx`. Un dossier étranger produirait des refus
/// (401), comptés par CrowdSec.
pub fn check_remote_location(url: &Url, username: &str) -> Result<(), SyncError> {
    let segments: Vec<&str> = url
        .path_segments()
        .map(Iterator::collect)
        .unwrap_or_default();
    validate_file_name(segments.last().copied().unwrap_or_default())?;
    if segments.first() == Some(&"dav") {
        if segments.len() != 3 {
            return Err(SyncError::InvalidUrl(
                "le coffre doit être à la racine du dossier du compte : /dav/<compte>/<coffre>.kdbx"
                    .into(),
            ));
        }
        if segments.get(1) != Some(&username) {
            return Err(SyncError::InvalidUrl(format!(
                "le dossier /dav/{}/ n'est pas celui du compte « {username} »",
                segments.get(1).copied().unwrap_or_default()
            )));
        }
    }
    Ok(())
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
            credentials_rejected_utc: None,
            last_written_sha256: Some("ab".repeat(32)),
        };
        state.save(&path).unwrap();
        assert_eq!(SyncState::load(&path), state);
    }

    #[test]
    fn state_written_before_the_suspension_field_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("etat.json");
        std::fs::write(
            &path,
            br#"{"remote_etag":"\"abc\"","local_dirty":false,"last_uploaded_sha256":null,"last_sync_utc":null}"#,
        )
        .unwrap();
        let state = SyncState::load(&path);
        assert_eq!(state.remote_etag.as_deref(), Some("\"abc\""));
        assert!(!state.local_dirty);
        assert!(state.credentials_rejected_utc.is_none());
        // Sans empreinte, le fichier sera réécrit avant le prochain envoi.
        assert!(state.last_written_sha256.is_none());
    }

    #[test]
    fn vault_names_must_not_look_temporary() {
        for name in ["coffre.kdbx", "Coffre familial.KDBX"] {
            assert!(validate_file_name(name).is_ok(), "{name}");
        }
        for name in [
            "",
            ".coffre.kdbx",
            "coffre.kdbx.tmp",
            "coffre.kdbx~",
            "coffre.kdbx.lock",
            "coffre.txt",
        ] {
            assert!(
                matches!(validate_file_name(name), Err(SyncError::InvalidUrl(_))),
                "{name}"
            );
        }
    }

    #[test]
    fn vaults_live_at_the_root_of_their_account_folder() {
        let url = |u: &str| Url::parse(u).unwrap();
        assert!(
            check_remote_location(
                &url("https://coffre.ligrivs.com/dav/hermann/coffre.kdbx"),
                "hermann"
            )
            .is_ok()
        );
        for (address, user) in [
            (
                "https://coffre.ligrivs.com/dav/hermann/sous/coffre.kdbx",
                "hermann",
            ),
            ("https://coffre.ligrivs.com/dav/coffre.kdbx", "hermann"),
            (
                "https://coffre.ligrivs.com/dav/autre/coffre.kdbx",
                "hermann",
            ),
            (
                "https://coffre.ligrivs.com/dav/hermann/.coffre.kdbx",
                "hermann",
            ),
        ] {
            assert!(
                matches!(
                    check_remote_location(&url(address), user),
                    Err(SyncError::InvalidUrl(_))
                ),
                "{address}"
            );
        }
        // Autre serveur WebDAV : seules les règles de nom s'appliquent.
        assert!(
            check_remote_location(&url("https://nas.exemple/partage/coffres/coffre.kdbx"), "h")
                .is_ok()
        );
    }

    #[test]
    fn oversized_uploads_are_refused_before_any_network_access() {
        // Adresse en .invalid : aucune résolution possible ; le refus doit
        // venir du contrôle local.
        let transport =
            WebDavTransport::new("https://coffre.invalid/dav/h/coffre.kdbx", "h", "x").unwrap();
        let body = vec![0u8; 52_428_801];
        assert!(matches!(
            transport.store(&body, &Precondition::IfNoneMatchAny),
            Err(SyncError::TooLarge)
        ));
    }

    #[test]
    fn an_unreadable_authority_certificate_is_refused() {
        assert!(matches!(
            WebDavTransport::with_root_ca(
                "https://127.0.0.1:18443/dav/h/coffre.kdbx",
                "h",
                "x",
                b"pas un certificat"
            ),
            Err(SyncError::InvalidCertificate(_))
        ));
    }
}
