//! Réglage de la synchronisation et bilan d'un échange avec le serveur.
//!
//! L'adresse, le compte et le mot de passe du serveur « coffre » sont rangés
//! dans le coffre lui-même, dans une entrée réservée (décision D4) : chiffrés,
//! transmis aux autres terminaux avec le reste, et jamais écrits ailleurs.

use std::time::Duration;

use ligrivsstore_core::sync::{SyncError, validate_file_name};
use ligrivsstore_core::{Error, SyncReport, TransportOptions, WebDavTransport};

use crate::error::AppError;

/// Serveur proposé par défaut.
pub const DEFAULT_SERVER: &str = "https://coffre.ligrivs.com";
/// Nom du coffre proposé par défaut sur le serveur.
pub const DEFAULT_FILE: &str = "coffre.kdbx";

/// Titre de l'entrée réservée, tel que l'affichent les autres applications
/// KeePass.
pub const SYNC_ENTRY_TITLE: &str = "Serveur de synchronisation (ligrivsstore)";
/// Notes de l'entrée réservée.
pub const SYNC_ENTRY_NOTES: &str = "Entrée réservée à ligrivsstore : adresse, compte et mot de passe \
du serveur « coffre ». Modifiez-la depuis l'écran Synchronisation de l'application.";

/// Délai d'établissement de la connexion.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Durée maximale d'un échange : un coffre de quelques centaines d'entrées
/// pèse moins de 1 Mo, et la session reste occupée pendant l'échange.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Emplacement d'un coffre sur le serveur « coffre ».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncTarget {
    /// Adresse du serveur, sans chemin (`https://coffre.ligrivs.com`).
    pub server: String,
    /// Compte WebDAV, qui est aussi le nom du dossier.
    pub account: String,
    /// Nom du fichier du coffre (`coffre.kdbx`).
    pub file: String,
}

impl SyncTarget {
    /// Vérifie et normalise les trois éléments saisis.
    pub fn new(server: &str, account: &str, file: &str) -> Result<Self, AppError> {
        let server = server.trim().trim_end_matches('/').to_owned();
        let account = account.trim().to_owned();
        let file = match file.trim() {
            "" => DEFAULT_FILE.to_owned(),
            file => file.to_owned(),
        };
        let lowered = server.to_ascii_lowercase();
        if !(lowered.starts_with("https://") || lowered.starts_with("http://")) {
            return Err(invalid("adresse du serveur : elle commence par https://"));
        }
        let host_part = server
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or_default();
        if host_part.is_empty() || host_part.contains(['/', '?', '#', '@']) {
            return Err(invalid(
                "adresse du serveur : seulement le nom du serveur, par exemple https://coffre.ligrivs.com",
            ));
        }
        if account.is_empty()
            || !account
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return Err(invalid(
                "compte : lettres sans accent, chiffres, tiret, point ou soulignement",
            ));
        }
        if file.contains(['/', '\\']) {
            return Err(invalid(
                "nom du coffre sur le serveur : un nom de fichier seul",
            ));
        }
        validate_file_name(&file).map_err(|e| invalid(e.to_string()))?;
        Ok(Self {
            server,
            account,
            file,
        })
    }

    /// Retrouve les trois éléments dans une adresse complète
    /// (`https://serveur/dav/<compte>/<coffre>.kdbx`).
    pub fn from_url(url: &str) -> Option<Self> {
        let (scheme, rest) = url.split_once("://")?;
        let (host, path) = rest.split_once('/')?;
        let mut segments = path.split('/');
        let (Some("dav"), Some(account), Some(file), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return None;
        };
        Some(Self {
            server: format!("{scheme}://{host}"),
            account: account.to_owned(),
            file: file.to_owned(),
        })
    }

    /// Adresse complète du coffre sur le serveur.
    pub fn url(&self) -> String {
        format!("{}/dav/{}/{}", self.server, self.account, self.file)
    }

    /// Prépare l'accès WebDAV ; `root_ca_pem` ne sert qu'aux bancs d'essai.
    pub fn transport(
        &self,
        password: &str,
        root_ca_pem: Option<&[u8]>,
    ) -> Result<WebDavTransport, AppError> {
        if password.is_empty() {
            return Err(AppError::new(
                "parametre_invalide",
                "mot de passe du serveur manquant",
            ));
        }
        let options = TransportOptions {
            connect_timeout: CONNECT_TIMEOUT,
            request_timeout: REQUEST_TIMEOUT,
            root_ca_pem: root_ca_pem.map(<[u8]>::to_vec),
        };
        WebDavTransport::with_options(&self.url(), &self.account, password, &options)
            .map_err(|e| invalid(e.to_string()))
    }
}

/// Bilan d'une synchronisation, pour l'interface et pour le pilote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    /// Échange réussi.
    Done {
        /// Coffre du serveur téléchargé.
        downloaded: bool,
        /// Coffre local envoyé.
        uploaded: bool,
        /// Entrées ajoutées, modifiées ou supprimées par la fusion.
        merged: usize,
    },
    /// Serveur injoignable ou indisponible : nouvel essai plus tard.
    Offline(String),
    /// Identifiants refusés : plus aucun essai avant une nouvelle saisie
    /// (CrowdSec bannit l'adresse après cinq refus en rafale).
    Suspended(String),
    /// Échec qui demande une action (clé différente, coffre illisible…).
    Failed(String),
    /// Synchronisation non réglée.
    NotConfigured,
    /// Coffre verrouillé.
    Locked,
}

impl SyncOutcome {
    /// Bilan d'un appel au noyau.
    pub fn from_result(result: Result<SyncReport, Error>) -> Self {
        match result {
            Ok(report) => Self::Done {
                downloaded: report.downloaded,
                uploaded: report.uploaded,
                merged: report.merge.created + report.merge.updated + report.merge.deleted,
            },
            Err(Error::Sync(error)) => match error {
                SyncError::Unauthorized | SyncError::CredentialsSuspended(_) => {
                    Self::Suspended(error.to_string())
                }
                SyncError::Network(_) | SyncError::TooManyConflicts | SyncError::UnstableEtag => {
                    Self::Offline(error.to_string())
                }
                SyncError::UnexpectedStatus(status) if status >= 500 => Self::Offline(format!(
                    "le serveur ne répond pas pour l'instant (code {status})"
                )),
                other => Self::Failed(other.to_string()),
            },
            Err(other) => Self::Failed(other.to_string()),
        }
    }
}

fn invalid(message: impl Into<String>) -> AppError {
    AppError::new("parametre_invalide", message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_are_checked_and_composed() {
        let target = SyncTarget::new(" https://coffre.ligrivs.com/ ", "hermann", "").unwrap();
        assert_eq!(
            target.url(),
            "https://coffre.ligrivs.com/dav/hermann/coffre.kdbx"
        );
        assert_eq!(SyncTarget::from_url(&target.url()), Some(target));

        for (server, account, file) in [
            ("coffre.ligrivs.com", "hermann", "coffre.kdbx"),
            ("https://coffre.ligrivs.com/dav", "hermann", "coffre.kdbx"),
            (
                "https://hermann:secret@coffre.ligrivs.com",
                "hermann",
                "coffre.kdbx",
            ),
            ("https://coffre.ligrivs.com", "", "coffre.kdbx"),
            ("https://coffre.ligrivs.com", "her mann", "coffre.kdbx"),
            ("https://coffre.ligrivs.com", "hermann", "coffre.tmp"),
            ("https://coffre.ligrivs.com", "hermann", ".coffre.kdbx"),
            (
                "https://coffre.ligrivs.com",
                "hermann",
                "dossier/coffre.kdbx",
            ),
            ("https://coffre.ligrivs.com", "hermann", "coffre.txt"),
        ] {
            assert!(
                SyncTarget::new(server, account, file).is_err(),
                "{server} {account} {file}"
            );
        }
        assert_eq!(
            SyncTarget::from_url("https://serveur/autre/chemin.kdbx"),
            None
        );
    }

    #[test]
    fn an_insecure_remote_address_is_refused_by_the_transport() {
        let target =
            SyncTarget::new("http://coffre.ligrivs.com", "hermann", "coffre.kdbx").unwrap();
        let error = target.transport("mot-de-passe", None).unwrap_err();
        assert!(error.message.contains("https"), "{}", error.message);
        // La machine locale reste admise en http:// (bancs d'essai).
        let local = SyncTarget::new("http://127.0.0.1:18081", "recette1", "coffre.kdbx").unwrap();
        assert!(local.transport("mot-de-passe", None).is_ok());
        assert!(local.transport("", None).is_err());
    }

    #[test]
    fn outcomes_are_classified() {
        let suspended = SyncOutcome::from_result(Err(Error::Sync(SyncError::Unauthorized)));
        assert!(matches!(suspended, SyncOutcome::Suspended(_)));
        let offline =
            SyncOutcome::from_result(Err(Error::Sync(SyncError::Network("délai".into()))));
        assert!(matches!(offline, SyncOutcome::Offline(_)));
        let down = SyncOutcome::from_result(Err(Error::Sync(SyncError::UnexpectedStatus(502))));
        assert!(matches!(down, SyncOutcome::Offline(_)));
        let wrong_key = SyncOutcome::from_result(Err(Error::Sync(SyncError::RemoteWrongKey)));
        assert!(matches!(wrong_key, SyncOutcome::Failed(_)));
        let done = SyncOutcome::from_result(Ok(SyncReport::default()));
        assert_eq!(
            done,
            SyncOutcome::Done {
                downloaded: false,
                uploaded: false,
                merged: 0
            }
        );
    }
}
