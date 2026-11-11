//! Intégration à Windows de l'application de bureau **ligrivsstore**.
//!
//! - [`watch_system_events`] : verrouillage de la session Windows et mise en
//!   veille, qui doivent verrouiller le coffre ;
//! - [`clipboard`] : copie d'un secret hors de l'historique du presse-papiers
//!   (Windows + V) et du presse-papiers cloud, puis effacement différé.
//!
//! C'est le seul paquet du dépôt qui appelle directement Windows, et le seul
//! où du code `unsafe` est admis, cantonné au module `systeme_windows`
//! (décision 0011). Hors de Windows, ces fonctions ne font rien ou répondent
//! [`WinError::Unsupported`] : le reste du dépôt se compile et se teste sous
//! Linux.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod clipboard;
#[cfg(windows)]
mod systeme_windows;

/// Événement du système après lequel le coffre doit être verrouillé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemEvent {
    /// Session verrouillée (Windows + L, écran de veille protégé), fermée, ou
    /// déconnectée (changement d'utilisateur, bureau à distance).
    SessionLocked,
    /// Mise en veille ou veille prolongée.
    Suspending,
}

/// Erreur d'un appel à Windows.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WinError {
    /// La surveillance est déjà en place dans ce processus.
    #[error("la surveillance du système est déjà en place")]
    AlreadyWatching,
    /// Fonction de Windows en échec.
    #[error("{function} a échoué (code Windows {code})")]
    Api {
        /// Fonction appelée.
        function: &'static str,
        /// Code renvoyé par `GetLastError`.
        code: u32,
    },
    /// Presse-papiers indisponible ou refusé.
    #[error("presse-papiers : {0}")]
    Clipboard(String),
    /// Fil de surveillance impossible à démarrer.
    #[error("surveillance du système : {0}")]
    Thread(String),
    /// Fonction propre à Windows.
    #[error("fonction disponible sous Windows seulement")]
    Unsupported,
}

/// Surveille le verrouillage de la session et la mise en veille.
///
/// `handler` est appelé depuis un fil dédié, qui doit rester libre : il ne
/// doit que transmettre l'événement (par un canal, par exemple). Hors de
/// Windows, rien n'est surveillé.
pub fn watch_system_events(
    handler: impl Fn(SystemEvent) + Send + Sync + 'static,
) -> Result<(), WinError> {
    #[cfg(windows)]
    {
        systeme_windows::watch(Box::new(handler)).map(|_| ())
    }
    #[cfg(not(windows))]
    {
        let _ = handler;
        Ok(())
    }
}
