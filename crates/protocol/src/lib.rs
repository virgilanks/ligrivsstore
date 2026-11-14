//! Protocole entre l'extension de navigateur et l'application **ligrivsstore**
//! (note de conception n° 3, sections 6.1 et 6.2 ; décision 0012).
//!
//! Le chemin d'un message : extension (service worker) → navigateur →
//! relais `ligrivsstore-pont` (messagerie native, entrée et sortie standard)
//! → canal nommé → application. Le relais ne fait que transmettre : il ne
//! déchiffre rien.
//!
//! - [`frame`] : trames de la messagerie native, une longueur sur 32 bits puis
//!   un message JSON, 1 Mio au plus ;
//! - [`message`] : les messages, en clair pour l'appairage et l'ouverture de
//!   session, chiffrés ensuite ;
//! - [`crypto`] : clés X25519, empreinte d'appairage, clés de session
//!   (HKDF-SHA256) et chiffrement AES-256-GCM avec compteur contre le rejeu.
//!
//! L'extension met en œuvre le même protocole en TypeScript, avec l'API Web
//! Crypto ; les vecteurs d'essai de `tests/vecteurs.json` sont vérifiés des
//! deux côtés.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod crypto;
pub mod frame;
pub mod message;

pub use crypto::{Identity, Role, Session, fingerprint};
pub use frame::{MAX_FRAME, read_frame, write_frame};
pub use message::{Envelope, PairState, Proximity, Request, Response, SiteEntry};

/// Version du protocole, portée par chaque message (`"v"`).
pub const VERSION: u32 = 1;

/// Nom déclaré auprès des navigateurs pour la messagerie native.
pub const HOST_NAME: &str = "com.ligrivs.ligrivsstore";

/// Identifiants des extensions admises. Pour l'instant, la version de
/// développement, dont l'identifiant découle de la clé publique de son
/// manifeste ; ceux du Chrome Web Store et d'Edge Add-ons s'ajouteront à la
/// publication (décision D2).
pub const EXTENSION_IDS: &[&str] = &["pbjfabapbnileccikicpifdnhkocnlbb"];

/// Vrai pour l'origine d'une extension admise : `chrome-extension://<id>/`,
/// telle que le navigateur la passe au relais.
pub fn extension_origin_allowed(origin: &str) -> bool {
    origin
        .strip_prefix("chrome-extension://")
        .and_then(|rest| rest.strip_suffix('/'))
        .is_some_and(|id| EXTENSION_IDS.contains(&id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_listed_extensions_are_allowed() {
        assert!(extension_origin_allowed(
            "chrome-extension://pbjfabapbnileccikicpifdnhkocnlbb/"
        ));
        for origin in [
            "chrome-extension://pbjfabapbnileccikicpifdnhkocnlbb",
            "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
            "https://pbjfabapbnileccikicpifdnhkocnlbb/",
            "chrome-extension://pbjfabapbnileccikicpifdnhkocnlbb/x/",
            "",
        ] {
            assert!(!extension_origin_allowed(origin), "{origin}");
        }
    }
}

/// Erreurs du protocole.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// Lecture ou écriture d'une trame.
    #[error("échange interrompu : {0}")]
    Io(#[from] std::io::Error),
    /// Trame plus grande que la limite.
    #[error("message trop grand : {0} octets (1 Mio au plus)")]
    TooLarge(usize),
    /// Message illisible ou incomplet.
    #[error("message illisible : {0}")]
    Malformed(String),
    /// Version du protocole inconnue.
    #[error("version du protocole non prise en charge : {0}")]
    Version(u32),
    /// Clé publique invalide ou échange Diffie-Hellman sans contribution.
    #[error("clé refusée")]
    BadKey,
    /// Message déjà reçu, ou reçu dans le désordre.
    #[error("message rejoué ou hors séquence (attendu {expected}, reçu {got})")]
    Replay {
        /// Compteur attendu.
        expected: u64,
        /// Compteur reçu.
        got: u64,
    },
    /// Authentification du message en échec : altéré, tronqué ou d'une
    /// autre session.
    #[error("message altéré ou d'une autre session")]
    Tampered,
    /// Trop de messages dans la session.
    #[error("session épuisée : rouvrir la liaison")]
    Exhausted,
    /// Aléa du système indisponible.
    #[error("aléa indisponible")]
    Random,
}
