//! Logique de l'application de bureau **ligrivsstore**, indépendante de
//! l'interface.
//!
//! La coquille Tauri (`apps/windows/src-tauri`) ne fait que relayer les
//! commandes de l'interface vers une [`Session`]. Tout ce qui a un sens
//! métier est ici, testé sous Linux et sous Windows sans fenêtre :
//!
//! - [`Session`] : coffre ouvert ou verrouillé, entrées, enregistrement ;
//! - [`settings`] : dernier coffre ouvert et emplacement de son fichier clé ;
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

pub mod dto;
mod error;
mod session;
pub mod settings;
mod strength;

pub use error::AppError;
pub use session::{CALIBRATION_TARGET, Session, generate_password};
pub use strength::{MIN_PASSPHRASE_CHARS, passphrase_strength};
