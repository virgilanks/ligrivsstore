//! Intégration à Windows de l'application de bureau **ligrivsstore**.
//!
//! - [`watch_system_events`] : verrouillage de la session Windows et mise en
//!   veille, qui doivent verrouiller le coffre ;
//! - [`clipboard`] : copie d'un secret hors de l'historique du presse-papiers
//!   (Windows + V) et du presse-papiers cloud, puis effacement différé ;
//! - [`canal`] : canal nommé entre le relais de messagerie native et
//!   l'application, réservé au compte Windows ;
//! - [`protect_secret`] et [`unprotect_secret`] : protection des clés par
//!   DPAPI, liée au compte Windows.
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

pub mod canal;
pub mod clipboard;
#[cfg(windows)]
mod systeme_windows;

use zeroize::Zeroizing;

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
    /// Canal local indisponible.
    #[error("canal local : {0}")]
    Channel(String),
}

/// Chiffre une donnée pour le seul compte Windows courant (DPAPI) : un autre
/// compte, ou le disque lu depuis un autre système, ne peut pas la relire.
pub fn protect_secret(data: &[u8], description: &str) -> Result<Vec<u8>, WinError> {
    #[cfg(windows)]
    {
        systeme_windows::protect(data, description)
    }
    #[cfg(not(windows))]
    {
        let _ = (data, description);
        Err(WinError::Unsupported)
    }
}

/// Déchiffre une donnée protégée par [`protect_secret`], sous le même compte.
pub fn unprotect_secret(blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, WinError> {
    #[cfg(windows)]
    {
        systeme_windows::unprotect(blob)
    }
    #[cfg(not(windows))]
    {
        let _ = blob;
        Err(WinError::Unsupported)
    }
}

/// Identifiant de sécurité (SID) du compte Windows qui exécute le processus.
pub fn current_user_sid() -> Result<String, WinError> {
    #[cfg(windows)]
    {
        systeme_windows::current_user_sid()
    }
    #[cfg(not(windows))]
    {
        Err(WinError::Unsupported)
    }
}

/// Lance un programme détaché : sans console, sans les entrées et sorties
/// standard du processus courant (sous Windows, elles ne sont plus
/// héritables), et sans l'attendre.
pub fn spawn_detached(program: &std::path::Path, args: &[&str]) -> Result<(), WinError> {
    let mut command = std::process::Command::new(program);
    command
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        const FLAGS: u32 = 0x0000_0008 | 0x0000_0200;
        systeme_windows::stop_std_handle_inheritance();
        command.creation_flags(FLAGS);
    }
    command
        .spawn()
        .map(|_| ())
        .map_err(|e| WinError::Thread(format!("lancement de {} : {e}", program.display())))
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
