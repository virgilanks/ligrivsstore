//! Coffre local d'un terminal et boucle de synchronisation.
//!
//! [`LocalVault`] réunit le fichier du coffre, sa clé, ses sauvegardes et son
//! état de synchronisation. C'est le point d'entrée des applications :
//! ouvrir, modifier, enregistrer, synchroniser.
//!
//! ## Boucle de synchronisation
//!
//! 1. Télécharger le coffre du serveur s'il a changé (`If-None-Match`). Si son
//!    étiquette est faible (écriture dans la seconde), attendre puis relire.
//! 2. Si ce n'est pas la version que ce terminal vient d'envoyer, l'ouvrir et la
//!    fusionner dans le coffre local. Un coffre distant illisible ou chiffré
//!    avec une autre clé arrête tout : rien n'est envoyé.
//! 3. S'il y a des modifications locales (ou aucun coffre sur le serveur) :
//!    enregistrer localement (écriture atomique et relecture), puis envoyer
//!    exactement ces octets avec `If-Match` (ou `If-None-Match: *`).
//! 4. Envoi refusé (412) : un autre terminal a écrit entre-temps ; reprendre à
//!    l'étape 1.
//!
//! Après un envoi, l'étiquette renvoyée par Apache est faible : elle n'est pas
//! conservée. La synchronisation suivante télécharge le coffre et reconnaît sa
//! propre version à son empreinte SHA-256, sans fusion inutile.
//!
//! Un refus d'identifiants (401) suspend la synchronisation, état enregistré,
//! jusqu'à [`LocalVault::accept_new_credentials`] : une application qui
//! réessaierait seule ferait bannir l'adresse de tout le foyer par CrowdSec.

use std::path::{Path, PathBuf};

use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::header::OpenLimits;
use crate::kdf::KdfParams;
use crate::storage::{BackupInfo, LocalStore};
use crate::sync::{
    Fetch, Precondition, StoreOutcome, SyncError, SyncOptions, SyncReport, SyncState, Transport,
};
use crate::vault::{Vault, VaultKey};

/// Nombre de sauvegardes locales conservées.
pub const DEFAULT_BACKUPS: usize = 10;

const STATE_SUFFIX: &str = ".synchro.json";

/// Coffre local d'un terminal.
#[derive(Debug)]
pub struct LocalVault {
    store: LocalStore,
    key: VaultKey,
    limits: OpenLimits,
    vault: Vault,
    state: SyncState,
}

impl LocalVault {
    /// Crée un nouveau coffre à `path` et l'enregistre.
    pub fn create(
        path: impl Into<PathBuf>,
        name: &str,
        key: VaultKey,
        kdf: KdfParams,
    ) -> Result<Self> {
        let store = LocalStore::new(path, DEFAULT_BACKUPS);
        if store.exists() {
            return Err(Error::AlreadyExists(store.path().display().to_string()));
        }
        let vault = Vault::create(name, kdf)?;
        let mut local = Self {
            store,
            key,
            limits: OpenLimits::default(),
            vault,
            state: SyncState::unknown(),
        };
        local.save()?;
        Ok(local)
    }

    /// Ouvre le coffre enregistré à `path`.
    pub fn open(path: impl Into<PathBuf>, key: VaultKey, limits: OpenLimits) -> Result<Self> {
        let store = LocalStore::new(path, DEFAULT_BACKUPS);
        let bytes = store.read()?;
        let vault = Vault::open(&bytes, &key, &limits)?;
        let state = SyncState::load(&store.sibling(STATE_SUFFIX));
        Ok(Self {
            store,
            key,
            limits,
            vault,
            state,
        })
    }

    /// Installe sur ce terminal le coffre déjà présent sur le serveur (ajout
    /// d'un terminal).
    pub fn clone_from_remote(
        path: impl Into<PathBuf>,
        key: VaultKey,
        limits: OpenLimits,
        transport: &dyn Transport,
    ) -> Result<Self> {
        let store = LocalStore::new(path, DEFAULT_BACKUPS);
        if store.exists() {
            return Err(Error::AlreadyExists(store.path().display().to_string()));
        }
        let (body, etag) = match transport.fetch(None)? {
            Fetch::Found { body, etag } => (body, etag),
            Fetch::NotFound => return Err(SyncError::RemoteMissing.into()),
            Fetch::NotModified => return Err(SyncError::UnexpectedStatus(304).into()),
        };
        let vault = Vault::open(&body, &key, &limits).map_err(remote_error)?;
        store.write_verified(&body, |b| Vault::open(b, &key, &limits).map(|_| ()))?;
        let state = SyncState {
            // Une étiquette faible ne vaut rien pour un envoi : on relira.
            remote_etag: etag.filter(|e| !e.is_weak()).map(|e| e.as_str().to_owned()),
            local_dirty: false,
            last_uploaded_sha256: None,
            last_sync_utc: Some(now()),
            credentials_rejected_utc: None,
        };
        let local = Self {
            store,
            key,
            limits,
            vault,
            state,
        };
        local.save_state()?;
        Ok(local)
    }

    /// Chemin du coffre.
    pub fn path(&self) -> &Path {
        self.store.path()
    }

    /// Coffre en lecture.
    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Coffre en écriture ; appeler [`LocalVault::save`] ensuite.
    pub fn vault_mut(&mut self) -> &mut Vault {
        &mut self.vault
    }

    /// État de synchronisation.
    pub fn sync_state(&self) -> &SyncState {
        &self.state
    }

    /// Sauvegardes locales, de la plus récente à la plus ancienne.
    pub fn backups(&self) -> Result<Vec<BackupInfo>> {
        self.store.backups()
    }

    /// Enregistre le coffre (écriture atomique et relecture de contrôle) et le
    /// marque comme à envoyer.
    pub fn save(&mut self) -> Result<()> {
        self.write_local()?;
        self.state.local_dirty = true;
        self.save_state()
    }

    /// Synchronise avec le serveur (voir la description du module).
    pub fn sync(&mut self, transport: &dyn Transport, options: &SyncOptions) -> Result<SyncReport> {
        // Après un refus d'identifiants, aucune nouvelle tentative avant une
        // nouvelle saisie : CrowdSec bannit l'adresse après cinq échecs en rafale.
        if let Some(since) = &self.state.credentials_rejected_utc {
            return Err(SyncError::CredentialsSuspended(since.clone()).into());
        }
        let outcome = self.sync_loop(transport, options);
        if matches!(outcome, Err(Error::Sync(SyncError::Unauthorized))) {
            self.state.credentials_rejected_utc = Some(now());
            self.save_state()?;
        }
        outcome
    }

    /// Lève la suspension de la synchronisation, après une nouvelle saisie des
    /// identifiants WebDAV par l'utilisateur.
    pub fn accept_new_credentials(&mut self) -> Result<()> {
        if self.state.credentials_rejected_utc.take().is_some() {
            self.save_state()?;
        }
        Ok(())
    }

    fn sync_loop(
        &mut self,
        transport: &dyn Transport,
        options: &SyncOptions,
    ) -> Result<SyncReport> {
        let mut report = SyncReport::default();
        let mut attempts = 0;
        loop {
            attempts += 1;
            if attempts > options.max_attempts {
                return Err(SyncError::TooManyConflicts.into());
            }

            // 1. Téléchargement conditionnel.
            let known = self.state.remote_etag.clone();
            let mut local_changed = false;
            let (remote_present, remote_etag) = match transport.fetch(known.as_deref())? {
                Fetch::NotModified => match known {
                    Some(etag) => (true, Some(etag)),
                    None => return Err(SyncError::UnexpectedStatus(304).into()),
                },
                Fetch::NotFound => (false, None),
                Fetch::Found { body, etag } => {
                    let etag = etag.ok_or(SyncError::MissingEtag)?;
                    if etag.is_weak() {
                        report.weak_waits += 1;
                        if report.weak_waits > options.max_weak_waits {
                            return Err(SyncError::UnstableEtag.into());
                        }
                        std::thread::sleep(options.weak_etag_wait);
                        attempts -= 1;
                        continue;
                    }
                    report.downloaded = true;
                    // 2. Fusion, sauf s'il s'agit de notre propre envoi.
                    if self.state.last_uploaded_sha256.as_deref()
                        != Some(sha256_hex(&body).as_str())
                    {
                        let remote =
                            Vault::open(&body, &self.key, &self.limits).map_err(remote_error)?;
                        let merge = self.vault.merge_from(&remote)?;
                        local_changed = !merge.is_empty();
                        report.merge.absorb(merge);
                    }
                    (true, Some(etag.as_str().to_owned()))
                }
            };

            // 3. Rien à envoyer : enregistrer le résultat de la fusion, s'il y en a un.
            if !self.state.local_dirty && remote_present {
                if local_changed {
                    self.write_local()?;
                }
                self.state.remote_etag = remote_etag;
                self.state.last_sync_utc = Some(now());
                self.save_state()?;
                return Ok(report);
            }

            // 3 bis. Envoi des octets enregistrés et vérifiés localement.
            let precondition = match remote_etag {
                Some(etag) => Precondition::IfMatch(etag),
                None => Precondition::IfNoneMatchAny,
            };
            let bytes = self.write_local()?;
            match transport.store(&bytes, &precondition)? {
                StoreOutcome::Stored => {
                    report.uploaded = true;
                    self.state.local_dirty = false;
                    self.state.last_uploaded_sha256 = Some(sha256_hex(&bytes));
                    self.state.remote_etag = None;
                    self.state.last_sync_utc = Some(now());
                    self.save_state()?;
                    return Ok(report);
                }
                // 4. Conflit : un autre terminal a écrit entre-temps.
                StoreOutcome::PreconditionFailed => {
                    report.conflicts += 1;
                    self.state.remote_etag = None;
                }
            }
        }
    }

    /// Sérialise, enregistre et vérifie le coffre ; renvoie les octets écrits.
    fn write_local(&mut self) -> Result<Vec<u8>> {
        let bytes = self.vault.to_bytes(&self.key)?;
        let key = &self.key;
        let limits = &self.limits;
        self.store.write_verified(&bytes, |written| {
            Vault::open(written, key, limits).map(|_| ())
        })?;
        Ok(bytes)
    }

    fn save_state(&self) -> Result<()> {
        self.state.save(&self.store.sibling(STATE_SUFFIX))
    }
}

/// Erreur d'ouverture d'un coffre venu du serveur.
fn remote_error(error: Error) -> Error {
    match error {
        Error::WrongKey => SyncError::RemoteWrongKey.into(),
        Error::Corrupt(reason) | Error::Unsupported(reason) | Error::KdfRejected(reason) => {
            SyncError::RemoteUnreadable(reason).into()
        }
        Error::TooLarge { size, max } => {
            SyncError::RemoteUnreadable(format!("{size} octets (maximum {max})")).into()
        }
        other => other,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn now() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
