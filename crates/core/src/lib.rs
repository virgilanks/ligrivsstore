//! Noyau de **ligrivsstore**, le gestionnaire de mots de passe du projet KEEPASS.
//!
//! Tout ce qui touche aux secrets est regroupé ici, pour n'être écrit, vérifié et
//! audité qu'une seule fois, puis appelé par chaque application (Windows, Android,
//! et plus tard iPhone) :
//!
//! - [`vault`] : ouverture et enregistrement des coffres au format ouvert KDBX 4 ;
//! - [`header`] : lecture de l'en-tête sans la clé et plafonds appliqués **avant**
//!   toute dérivation de clé ;
//! - [`kdf`] : politique de dérivation (Argon2id) et calibrage ;
//! - [`keyfile`] : fichiers clés au format XML 2.0 de KeePass ;
//! - [`storage`] : écriture atomique, relecture de contrôle, sauvegardes locales ;
//! - [`local`] : coffre local d'un terminal et boucle de synchronisation ;
//! - [`sync`] : échanges avec le serveur « coffre » (WebDAV, envoi conditionnel) ;
//! - [`generator`] : mots de passe et phrases de passe aléatoires.
//!
//! Le serveur ne voit jamais que des fichiers chiffrés : la fusion des
//! modifications faites sur plusieurs terminaux se fait ici, sur le terminal.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod error;
pub mod generator;
pub mod header;
pub mod kdf;
pub mod keyfile;
pub mod local;
pub mod storage;
pub mod sync;
pub mod vault;

pub use error::{Error, Result};
pub use header::OpenLimits;
pub use kdf::KdfParams;
pub use local::LocalVault;
pub use sync::{SyncError, SyncOptions, SyncReport, Transport, TransportOptions, WebDavTransport};
pub use vault::{
    EntryDetails, EntryInput, EntrySummary, MergeReport, ROLE_FIELD, RestoreReport, SYNC_ROLE,
    Vault, VaultKey,
};
