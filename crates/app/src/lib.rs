//! Logique de l'application de bureau **ligrivsstore**, indépendante de
//! l'interface.
//!
//! La coquille Tauri (`apps/windows/src-tauri`) ne fait que relayer les
//! commandes de l'interface vers une [`Session`]. Tout ce qui a un sens
//! métier est ici, testé sous Linux et sous Windows sans fenêtre :
//!
//! - [`Session`] : coffre ouvert ou verrouillé, entrées, enregistrement,
//!   synchronisation, installation depuis le serveur, sauvegardes ;
//! - [`Autopilot`] : verrouillage automatique, échéances de synchronisation,
//!   effacement du presse-papiers ;
//! - [`Monitor`] : état lisible par l'interface pendant que la session est
//!   occupée ;
//! - [`synchro`] : emplacement du coffre sur le serveur, bilan d'un échange ;
//! - [`liaison`] et [`navigateurs`] : liaison chiffrée avec l'extension de
//!   navigateur, appairage, navigateurs appairés ;
//! - [`settings`] : dernier coffre ouvert, fichier clé, délais ;
//! - [`dto`] : messages échangés avec l'interface (JSON) ;
//! - [`AppError`] : erreurs à afficher, avec un code stable et un message en
//!   français.
//!
//! Le coffre déverrouillé et sa clé restent dans ce processus : l'interface
//! reçoit des listes, et un mot de passe seulement quand on le lui demande
//! explicitement.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod autopilot;
pub mod dto;
mod error;
pub mod liaison;
pub mod monitor;
pub mod navigateurs;
mod session;
pub mod settings;
mod strength;
pub mod synchro;

pub use autopilot::{Action, Autopilot, LockReason};
pub use error::AppError;
pub use monitor::Monitor;
pub use session::{
    CALIBRATION_TARGET, INSTALL_PAUSE, Session, generate_passphrase, generate_password,
};
pub use strength::{MIN_PASSPHRASE_CHARS, passphrase_strength};
pub use synchro::{SyncOutcome, SyncTarget};
