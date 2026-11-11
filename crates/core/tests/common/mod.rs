//! Outils communs aux tests d'intégration.
#![allow(
    dead_code,
    unreachable_pub,
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;
use std::sync::Mutex;

use keepass::DatabaseKey;
use keepass::config::{DatabaseConfig, DatabaseVersion, KdfConfig};
use keepass::db::{Database, fields};
use ligrivsstore_core::sync::{ETag, Fetch, Precondition, StoreOutcome, SyncError, Transport};
use ligrivsstore_core::{EntryInput, KdfParams, VaultKey};
use zeroize::Zeroizing;

pub const PASSWORD: &str = "phrase de test non secrète";

/// Paramètres conformes à la politique, au coût minimal (tests rapides).
pub fn fast_kdf() -> KdfParams {
    KdfParams {
        iterations: ligrivsstore_core::kdf::MIN_ITERATIONS,
        ..KdfParams::default()
    }
}

pub fn key() -> VaultKey {
    VaultKey::new().with_password(PASSWORD)
}

pub fn entry(title: &str, password: &str) -> EntryInput {
    EntryInput {
        title: title.into(),
        url: format!("https://{}.exemple.test", title.to_lowercase()),
        username: "hermann@exemple.test".into(),
        password: Zeroizing::new(password.into()),
        notes: format!("Notes de {title} : accents éèà, guillemets « », emoji 🔐"),
    }
}

/// Coffre écrit directement par la bibliothèque, avec une dérivation minimale
/// (1 Mio, 1 passe) : sert de base aux tests aléatoires, pour qu'une tentative
/// d'ouverture coûte peu.
pub fn tiny_vault_bytes(password: &str) -> Vec<u8> {
    let mut config = DatabaseConfig::default();
    config.version = DatabaseVersion::KDB4(1);
    config.kdf_config = KdfConfig::Argon2id {
        iterations: 1,
        memory: 1024 * 1024,
        parallelism: 1,
        version: argon2::Version::Version13,
    };
    let mut db = Database::with_config(config);
    db.root_mut().add_entry().edit(|e| {
        e.set_unprotected(fields::TITLE, "Banque");
        e.set_unprotected(fields::USERNAME, "hermann");
        e.set_protected(fields::PASSWORD, "mot-de-passe");
    });
    let mut out = Vec::new();
    db.save(&mut out, DatabaseKey::new().with_password(password))
        .unwrap();
    out
}

/// Réécrit le dictionnaire des paramètres de dérivation (champ 11) d'un coffre
/// KDBX 4, le reste du fichier étant conservé tel quel.
pub fn rewrite_kdf_dictionary(bytes: &[u8], change: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut out = bytes[..12].to_vec();
    let mut position = 12;
    let mut change = Some(change);
    loop {
        let id = bytes[position];
        let length =
            u32::from_le_bytes(bytes[position + 1..position + 5].try_into().unwrap()) as usize;
        let mut value = bytes[position + 5..position + 5 + length].to_vec();
        position += 5 + length;
        if id == 11 {
            (change.take().unwrap())(&mut value);
        }
        out.push(id);
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(&value);
        if id == 0 {
            break;
        }
    }
    out.extend_from_slice(&bytes[position..]);
    out
}

/// Remplace la valeur d'un paramètre entier de 8 octets (« M », « I »).
pub fn set_u64_parameter(dictionary: &mut [u8], name: u8, value: u64) {
    let pattern = [0x05, 1, 0, 0, 0, name, 8, 0, 0, 0];
    let at = dictionary
        .windows(pattern.len())
        .position(|w| w == pattern)
        .expect("paramètre absent");
    dictionary[at + pattern.len()..at + pattern.len() + 8].copy_from_slice(&value.to_le_bytes());
}

/// Chemin de keepassxc-cli, ou `None` (test ignoré) s'il est absent.
/// Avec `LGS_REQUIRE_KEEPASSXC=1` (intégration continue), son absence est une
/// erreur.
pub fn keepassxc_cli() -> Option<PathBuf> {
    let found = std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(format!("keepassxc-cli{}", std::env::consts::EXE_SUFFIX)))
            .find(|candidate| candidate.is_file())
    });
    if found.is_none() {
        assert!(
            std::env::var("LGS_REQUIRE_KEEPASSXC").as_deref() != Ok("1"),
            "keepassxc-cli est exigé (LGS_REQUIRE_KEEPASSXC=1) mais introuvable"
        );
        eprintln!("keepassxc-cli introuvable : test d'interopérabilité ignoré");
    }
    found
}

/// Serveur WebDAV simulé en mémoire, avec les comportements d'Apache utiles
/// aux tests : étiquettes (fortes ou faibles), If-Match, If-None-Match.
#[derive(Default)]
pub struct MemoryServer {
    state: Mutex<ServerState>,
}

#[derive(Default)]
struct ServerState {
    body: Option<Vec<u8>>,
    version: u64,
    weak_reads: u32,
    concurrent_writes: Vec<Vec<u8>>,
    always_concurrent: Option<Vec<u8>>,
    stores: u32,
    rejected: u32,
    reject_credentials: bool,
    fetches: u32,
}

impl MemoryServer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn body(&self) -> Option<Vec<u8>> {
        self.state.lock().unwrap().body.clone()
    }

    /// Écriture directe, comme le ferait un autre terminal.
    pub fn put_raw(&self, bytes: Vec<u8>) {
        let mut s = self.state.lock().unwrap();
        s.body = Some(bytes);
        s.version += 1;
    }

    /// Les `n` prochains téléchargements portent une étiquette faible.
    pub fn weak_next_reads(&self, n: u32) {
        self.state.lock().unwrap().weak_reads = n;
    }

    /// Juste avant le prochain envoi, un autre terminal écrit `bytes`.
    pub fn concurrent_write_before_next_store(&self, bytes: Vec<u8>) {
        self.state.lock().unwrap().concurrent_writes.push(bytes);
    }

    /// Avant chaque envoi, un autre terminal écrit `bytes`.
    pub fn concurrent_write_before_every_store(&self, bytes: Vec<u8>) {
        self.state.lock().unwrap().always_concurrent = Some(bytes);
    }

    /// Envois acceptés.
    pub fn stores(&self) -> u32 {
        self.state.lock().unwrap().stores
    }

    /// Envois refusés (412).
    pub fn rejected(&self) -> u32 {
        self.state.lock().unwrap().rejected
    }

    /// Refuse (401) ou accepte les identifiants.
    pub fn reject_credentials(&self, reject: bool) {
        self.state.lock().unwrap().reject_credentials = reject;
    }

    /// Nombre de téléchargements demandés.
    pub fn fetches(&self) -> u32 {
        self.state.lock().unwrap().fetches
    }
}

impl Transport for MemoryServer {
    fn fetch(&self, if_none_match: Option<&str>) -> Result<Fetch, SyncError> {
        let mut s = self.state.lock().unwrap();
        s.fetches += 1;
        if s.reject_credentials {
            return Err(SyncError::Unauthorized);
        }
        let Some(body) = s.body.clone() else {
            return Ok(Fetch::NotFound);
        };
        let strong = format!("\"v{}\"", s.version);
        if s.weak_reads > 0 {
            s.weak_reads -= 1;
            return Ok(Fetch::Found {
                body,
                etag: ETag::parse(&format!("W/{strong}")),
            });
        }
        if if_none_match == Some(strong.as_str()) {
            return Ok(Fetch::NotModified);
        }
        Ok(Fetch::Found {
            body,
            etag: ETag::parse(&strong),
        })
    }

    fn store(&self, body: &[u8], precondition: &Precondition) -> Result<StoreOutcome, SyncError> {
        let mut s = self.state.lock().unwrap();
        if s.reject_credentials {
            return Err(SyncError::Unauthorized);
        }
        let concurrent = if s.concurrent_writes.is_empty() {
            s.always_concurrent.clone()
        } else {
            Some(s.concurrent_writes.remove(0))
        };
        if let Some(other) = concurrent {
            s.body = Some(other);
            s.version += 1;
        }
        let current = s.body.as_ref().map(|_| format!("\"v{}\"", s.version));
        let accepted = match precondition {
            // Comparaison forte, comme Apache : une étiquette faible échoue toujours.
            Precondition::IfMatch(etag) => current.as_deref() == Some(etag.as_str()),
            Precondition::IfNoneMatchAny => current.is_none(),
        };
        if !accepted {
            s.rejected += 1;
            return Ok(StoreOutcome::PreconditionFailed);
        }
        s.body = Some(body.to_vec());
        s.version += 1;
        s.stores += 1;
        Ok(StoreOutcome::Stored)
    }
}
