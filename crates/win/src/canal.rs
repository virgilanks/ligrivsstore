//! Canal local entre le relais `ligrivsstore-pont` et l'application.
//!
//! **Sous Windows** : canal nommé `\\.\pipe\ligrivsstore-<SID du compte>`.
//!
//! - Liste de contrôle d'accès explicite et protégée : seul le compte qui
//!   exécute l'application y a accès (`D:P(A;;GA;;;<SID>)`), pas les autres
//!   comptes du PC.
//! - Créé en première instance : si un autre programme a pris le nom avant
//!   l'application, la création échoue au lieu de partager le canal.
//! - Clients distants refusés (canal local seulement).
//!
//! **Ailleurs** (développement et essais sous Linux) : socket Unix dans un
//! dossier réservé au compte (droits 0700), fichier en 0600.
//!
//! La variable d'environnement `LIGRIVSSTORE_CANAL` désigne un autre canal,
//! pour les essais de bout en bout : nom du canal nommé sous Windows, chemin
//! du socket ailleurs.

use interprocess::local_socket::traits::{Listener as _, Stream as _};
use interprocess::local_socket::{Listener, ListenerOptions};

/// Liaison ouverte. `&Stream` lit et écrit : partagée par un `Arc`, elle se
/// lit sur un fil et s'écrit sur un autre.
pub use interprocess::local_socket::Stream;

use crate::WinError;

/// Variable d'environnement qui remplace le canal par défaut.
pub const CHANNEL_VARIABLE: &str = "LIGRIVSSTORE_CANAL";

/// Nom du canal : nom du canal nommé sous Windows, chemin du socket ailleurs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelName(String);

impl ChannelName {
    /// Canal du compte courant, ou celui de `LIGRIVSSTORE_CANAL`.
    pub fn for_current_user() -> Result<Self, WinError> {
        if let Some(custom) = std::env::var_os(CHANNEL_VARIABLE).filter(|v| !v.is_empty()) {
            return Ok(Self(custom.to_string_lossy().into_owned()));
        }
        default_name().map(Self)
    }

    /// Canal donné explicitement (essais).
    pub fn custom(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Le nom, tel quel.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(windows)]
fn default_name() -> Result<String, WinError> {
    Ok(format!("ligrivsstore-{}", crate::current_user_sid()?))
}

#[cfg(not(windows))]
fn default_name() -> Result<String, WinError> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .map(|dir| dir.join("ligrivsstore"))
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|v| !v.is_empty())
                .map(|home| std::path::PathBuf::from(home).join(".ligrivsstore"))
        })
        .ok_or_else(|| WinError::Channel("ni XDG_RUNTIME_DIR ni HOME".into()))?;
    Ok(base.join("canal.sock").to_string_lossy().into_owned())
}

fn channel_error(action: &str, error: std::io::Error) -> WinError {
    WinError::Channel(format!("{action} : {error}"))
}

/// Canal ouvert côté application.
#[derive(Debug)]
pub struct ChannelListener(Listener);

impl ChannelListener {
    /// Attend la liaison suivante.
    pub fn accept(&self) -> Result<Stream, WinError> {
        self.0
            .accept()
            .map_err(|e| channel_error("liaison entrante", e))
    }
}

/// Ouvre le canal côté application.
pub fn listen(name: &ChannelName) -> Result<ChannelListener, WinError> {
    let options = options(name)?;
    options.create_sync().map(ChannelListener).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AddrInUse
            || e.kind() == std::io::ErrorKind::PermissionDenied
        {
            WinError::Channel(format!(
                "le canal {} est déjà ouvert, par une autre instance ou un autre programme",
                name.as_str()
            ))
        } else {
            channel_error("ouverture du canal", e)
        }
    })
}

/// Rejoint le canal côté relais.
pub fn connect(name: &ChannelName) -> Result<Stream, WinError> {
    Stream::connect(socket_name(name)?).map_err(|e| channel_error("connexion au canal", e))
}

#[cfg(windows)]
fn socket_name(name: &ChannelName) -> Result<interprocess::local_socket::Name<'_>, WinError> {
    use interprocess::local_socket::{GenericNamespaced, ToNsName};
    name.as_str()
        .to_ns_name::<GenericNamespaced>()
        .map_err(|e| channel_error("nom du canal", e))
}

#[cfg(not(windows))]
fn socket_name(name: &ChannelName) -> Result<interprocess::local_socket::Name<'_>, WinError> {
    use interprocess::local_socket::{GenericFilePath, ToFsName};
    name.as_str()
        .to_fs_name::<GenericFilePath>()
        .map_err(|e| channel_error("nom du canal", e))
}

#[cfg(windows)]
fn options(name: &ChannelName) -> Result<ListenerOptions<'_>, WinError> {
    use interprocess::os::windows::local_socket::ListenerOptionsExt;
    use interprocess::os::windows::security_descriptor::SecurityDescriptor;
    let sid = crate::current_user_sid()?;
    let sddl = widestring::U16CString::from_str(format!("D:P(A;;GA;;;{sid})"))
        .map_err(|e| WinError::Channel(format!("descripteur de sécurité : {e}")))?;
    let descriptor = SecurityDescriptor::deserialize(&sddl)
        .map_err(|e| channel_error("descripteur de sécurité", e))?;
    Ok(ListenerOptions::new()
        .name(socket_name(name)?)
        .security_descriptor(descriptor))
}

#[cfg(not(windows))]
fn options(name: &ChannelName) -> Result<ListenerOptions<'_>, WinError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    use interprocess::os::unix::local_socket::ListenerOptionsExt;
    let path = std::path::Path::new(name.as_str());
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        if !dir.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|e| channel_error("dossier du canal", e))?;
        }
        let mode = std::fs::metadata(dir)
            .map_err(|e| channel_error("dossier du canal", e))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(WinError::Channel(format!(
                "dossier du canal ouvert à d'autres comptes ({:o}) : {}",
                mode & 0o777,
                dir.display()
            )));
        }
    }
    Ok(ListenerOptions::new()
        .name(socket_name(name)?)
        .try_overwrite(true)
        .mode(0o600))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::thread;

    use super::*;

    fn unique() -> String {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("ligrivsstore-essai-{}-{stamp}", std::process::id())
    }

    #[cfg(windows)]
    fn test_name() -> (ChannelName, ()) {
        (ChannelName::custom(unique()), ())
    }

    #[cfg(not(windows))]
    fn test_name() -> (ChannelName, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(unique());
        let name = ChannelName::custom(dir.join("canal.sock").to_string_lossy().into_owned());
        (name, dir)
    }

    #[test]
    fn the_relay_and_the_app_exchange_bytes_both_ways() {
        let (name, _guard) = test_name();
        let listener = listen(&name).unwrap();
        let server = thread::spawn(move || {
            let mut stream = listener.accept().unwrap();
            let mut request = [0u8; 5];
            stream.read_exact(&mut request).unwrap();
            stream.write_all(b"pong:").unwrap();
            stream.write_all(&request).unwrap();
        });
        // Lecture et écriture sur deux fils, comme dans le relais.
        let stream = Arc::new(connect(&name).unwrap());
        let writer = Arc::clone(&stream);
        thread::spawn(move || (&*writer).write_all(b"ping!").unwrap())
            .join()
            .unwrap();
        let mut answer = [0u8; 10];
        (&*stream).read_exact(&mut answer).unwrap();
        assert_eq!(&answer, b"pong:ping!");
        server.join().unwrap();
    }

    #[test]
    fn connecting_without_the_app_fails_at_once() {
        let (name, _guard) = test_name();
        assert!(matches!(connect(&name), Err(WinError::Channel(_))));
    }

    #[cfg(windows)]
    #[test]
    fn a_second_listener_cannot_take_an_open_channel() {
        let (name, _) = test_name();
        let _first = listen(&name).unwrap();
        assert!(matches!(listen(&name), Err(WinError::Channel(_))));
    }

    #[cfg(windows)]
    #[test]
    fn the_default_channel_belongs_to_the_account() {
        let name = default_name().unwrap();
        assert!(name.starts_with("ligrivsstore-S-1-5-"), "{name}");
    }

    #[cfg(not(windows))]
    #[test]
    fn the_socket_is_private_to_the_account() {
        use std::os::unix::fs::PermissionsExt;
        let (name, dir) = test_name();
        let _listener = listen(&name).unwrap();
        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        let socket_mode = std::fs::metadata(name.as_str())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(socket_mode, 0o600);
        std::fs::remove_dir_all(&dir).unwrap();

        // Dossier ouvert à tous : refusé.
        let (open, open_dir) = test_name();
        std::fs::create_dir_all(&open_dir).unwrap();
        std::fs::set_permissions(&open_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(listen(&open), Err(WinError::Channel(_))));
        std::fs::remove_dir_all(&open_dir).unwrap();
    }
}
