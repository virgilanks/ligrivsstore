//! Messages échangés, en JSON.
//!
//! **Enveloppes** ([`Envelope`], champ `type`) : chaque trame en porte une.
//!
//! | Sens | `type` | Rôle |
//! |---|---|---|
//! | relais → application | `bridge` | origine de l'extension appelante, lue par le relais dans ses arguments (la première trame de chaque liaison) |
//! | extension → application | `pair` | demande d'appairage : clé publique permanente de l'extension, nom du navigateur |
//! | application → extension | `pair-pending` | clé publique de l'application, numéro de la demande ; l'application affiche l'empreinte |
//! | application → extension | `pair-result` | confirmée, refusée ou expirée dans l'application |
//! | extension → application | `hello` | ouverture de session : clé permanente (appairée) et clé éphémère de l'extension |
//! | application → extension | `welcome` | clé éphémère de l'application et premier message chiffré, qui prouve qu'elle détient sa clé |
//! | les deux | `msg` | message chiffré : compteur `n` et chiffré `c` (Base64) |
//! | application → extension | `error` | erreur avant la session (version, appairage inconnu…) |
//!
//! **Messages chiffrés** ([`Request`] et [`Response`], champ `op`), une fois
//! la session ouverte. L'adresse de la page vient du navigateur (onglet lu
//! par le service worker), jamais de la page.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::crypto::KEY_LEN;
use crate::{ProtocolError, VERSION};

/// Enveloppe d'une trame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Envelope {
    /// Origine de l'extension, annoncée par le relais.
    Bridge {
        /// Version du protocole.
        v: u32,
        /// `chrome-extension://<identifiant>/`.
        origin: String,
    },
    /// Demande d'appairage.
    Pair {
        /// Version du protocole.
        v: u32,
        /// Clé publique permanente de l'extension (Base64).
        client: String,
        /// Navigateur, pour l'affichage (« Chrome », « Edge »).
        browser: String,
    },
    /// Demande d'appairage reçue, en attente de confirmation.
    PairPending {
        /// Version du protocole.
        v: u32,
        /// Clé publique permanente de l'application (Base64).
        app: String,
        /// Numéro de la demande.
        pairing: String,
    },
    /// Issue de la demande d'appairage.
    PairResult {
        /// Version du protocole.
        v: u32,
        /// Numéro de la demande.
        pairing: String,
        /// Issue.
        state: PairState,
    },
    /// Ouverture de session.
    Hello {
        /// Version du protocole.
        v: u32,
        /// Clé publique permanente de l'extension (Base64).
        client: String,
        /// Clé publique éphémère de l'extension (Base64).
        eph: String,
    },
    /// Session acceptée.
    Welcome {
        /// Version du protocole.
        v: u32,
        /// Clé publique éphémère de l'application (Base64).
        eph: String,
        /// Compteur du premier message chiffré (0).
        n: u64,
        /// Premier message chiffré : [`Response::Welcome`].
        c: String,
    },
    /// Message chiffré.
    Msg {
        /// Version du protocole.
        v: u32,
        /// Compteur.
        n: u64,
        /// Chiffré, étiquette comprise (Base64).
        c: String,
    },
    /// Erreur avant l'ouverture de la session.
    Error {
        /// Version du protocole.
        v: u32,
        /// Code stable, pour l'extension.
        code: String,
        /// Explication, en français.
        message: String,
    },
}

/// Issue d'une demande d'appairage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PairState {
    /// Confirmée dans l'application.
    Confirmed,
    /// Refusée dans l'application.
    Refused,
    /// Sans réponse dans le délai.
    Expired,
}

impl Envelope {
    /// Lit une trame ; refuse une autre version du protocole.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let envelope: Self =
            serde_json::from_slice(bytes).map_err(|e| ProtocolError::Malformed(e.to_string()))?;
        let version = envelope.version();
        if version != VERSION {
            return Err(ProtocolError::Version(version));
        }
        Ok(envelope)
    }

    /// Écrit la trame.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        serde_json::to_vec(self).map_err(|e| ProtocolError::Malformed(e.to_string()))
    }

    /// Version portée par l'enveloppe.
    pub fn version(&self) -> u32 {
        match self {
            Self::Bridge { v, .. }
            | Self::Pair { v, .. }
            | Self::PairPending { v, .. }
            | Self::PairResult { v, .. }
            | Self::Hello { v, .. }
            | Self::Welcome { v, .. }
            | Self::Msg { v, .. }
            | Self::Error { v, .. } => *v,
        }
    }

    /// Erreur à renvoyer avant la session.
    pub fn error(code: &str, message: &str) -> Self {
        Self::Error {
            v: VERSION,
            code: code.to_owned(),
            message: message.to_owned(),
        }
    }
}

/// Requête de l'extension, chiffrée.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum Request {
    /// État du coffre.
    Status {
        /// Numéro de la requête, repris dans la réponse.
        id: u32,
    },
    /// Entrées qui correspondent à la page ouverte.
    Entries {
        /// Numéro de la requête.
        id: u32,
        /// Adresse de la page, lue par le navigateur.
        url: String,
    },
    /// Montrer la fenêtre de l'application (pour déverrouiller le coffre).
    Show {
        /// Numéro de la requête.
        id: u32,
    },
}

/// Réponse de l'application, chiffrée.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum Response {
    /// Premier message de la session.
    Welcome {
        /// Nom de l'application.
        app: String,
        /// Version de l'application.
        version: String,
    },
    /// État du coffre.
    Status {
        /// Numéro de la requête.
        id: u32,
        /// Coffre déverrouillé.
        unlocked: bool,
    },
    /// Entrées de la page, de la plus proche à la plus éloignée.
    Entries {
        /// Numéro de la requête.
        id: u32,
        /// Entrées, sans mot de passe.
        entries: Vec<SiteEntry>,
    },
    /// Requête exécutée.
    Ok {
        /// Numéro de la requête.
        id: u32,
    },
    /// Requête refusée (coffre verrouillé, requête invalide…).
    Error {
        /// Numéro de la requête, s'il a pu être lu.
        id: Option<u32>,
        /// Code stable, pour l'extension.
        code: String,
        /// Explication, en français.
        message: String,
    },
}

/// Entrée proposée pour une page, sans mot de passe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteEntry {
    /// Identifiant de l'entrée.
    pub id: String,
    /// Titre.
    pub title: String,
    /// Identifiant de connexion.
    pub username: String,
    /// Proximité entre la page et l'adresse de l'entrée.
    pub proximity: Proximity,
    /// Page en `http://` : l'identifiant partirait sans chiffrement.
    pub insecure: bool,
}

/// Proximité, telle que transmise à l'extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Proximity {
    /// Même origine.
    SameOrigin,
    /// Même hôte, autre port ou schéma.
    SameHost,
    /// Autre sous-domaine du même domaine.
    Subdomain,
}

impl Request {
    /// Lit une requête déchiffrée.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        serde_json::from_slice(bytes).map_err(|e| ProtocolError::Malformed(e.to_string()))
    }

    /// Écrit la requête, avant chiffrement.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        serde_json::to_vec(self).map_err(|e| ProtocolError::Malformed(e.to_string()))
    }
}

impl Response {
    /// Lit une réponse déchiffrée.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        serde_json::from_slice(bytes).map_err(|e| ProtocolError::Malformed(e.to_string()))
    }

    /// Écrit la réponse, avant chiffrement.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        serde_json::to_vec(self).map_err(|e| ProtocolError::Malformed(e.to_string()))
    }
}

/// Clé publique en Base64.
pub fn encode_key(key: &[u8; KEY_LEN]) -> String {
    STANDARD.encode(key)
}

/// Lit une clé publique en Base64 (32 octets exactement).
pub fn decode_key(text: &str) -> Result<[u8; KEY_LEN], ProtocolError> {
    let bytes = STANDARD
        .decode(text)
        .map_err(|_| ProtocolError::Malformed("clé illisible".into()))?;
    <[u8; KEY_LEN]>::try_from(bytes.as_slice())
        .map_err(|_| ProtocolError::Malformed("clé de taille inattendue".into()))
}

/// Chiffré en Base64.
pub fn encode_bytes(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Lit un chiffré en Base64.
pub fn decode_bytes(text: &str) -> Result<Vec<u8>, ProtocolError> {
    STANDARD
        .decode(text)
        .map_err(|_| ProtocolError::Malformed("chiffré illisible".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelopes_have_a_stable_json_form() {
        let pair = Envelope::Pair {
            v: VERSION,
            client: "QUJD".into(),
            browser: "Chrome".into(),
        };
        assert_eq!(
            String::from_utf8(pair.encode().unwrap()).unwrap(),
            r#"{"type":"pair","v":1,"client":"QUJD","browser":"Chrome"}"#
        );
        let result =
            Envelope::decode(br#"{"type":"pair-result","v":1,"pairing":"p1","state":"confirmed"}"#)
                .unwrap();
        assert_eq!(
            result,
            Envelope::PairResult {
                v: 1,
                pairing: "p1".into(),
                state: PairState::Confirmed
            }
        );
        let msg = Envelope::decode(br#"{"type":"msg","v":1,"n":4294967295,"c":"AA=="}"#).unwrap();
        assert!(matches!(
            msg,
            Envelope::Msg {
                n: 4_294_967_295,
                ..
            }
        ));
    }

    #[test]
    fn other_versions_and_garbage_are_refused() {
        assert!(matches!(
            Envelope::decode(br#"{"type":"hello","v":2,"client":"a","eph":"b"}"#),
            Err(ProtocolError::Version(2))
        ));
        for bad in [
            &b"pas du json"[..],
            br#"{"type":"inconnu","v":1}"#,
            br#"{"v":1}"#,
            br#"{"type":"msg","v":1,"n":-1,"c":"AA=="}"#,
            br#"{"type":"msg","v":1,"c":"AA=="}"#,
            b"",
        ] {
            assert!(
                Envelope::decode(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn requests_and_responses_round_trip() {
        let request = Request::Entries {
            id: 3,
            url: "https://www.banque.fr/connexion".into(),
        };
        assert_eq!(
            Request::decode(&request.encode().unwrap()).unwrap(),
            request
        );
        let response = Response::Entries {
            id: 3,
            entries: vec![SiteEntry {
                id: "e1".into(),
                title: "Banque".into(),
                username: "hermann".into(),
                proximity: Proximity::Subdomain,
                insecure: false,
            }],
        };
        let text = String::from_utf8(response.encode().unwrap()).unwrap();
        assert!(text.contains(r#""proximity":"subdomain""#));
        assert_eq!(Response::decode(text.as_bytes()).unwrap(), response);
        assert!(
            Request::decode(br#"{"op":"reveal","id":1}"#).is_err(),
            "aucune autre requête"
        );
    }

    #[test]
    fn keys_must_be_exactly_32_bytes() {
        let key = [9u8; KEY_LEN];
        assert_eq!(decode_key(&encode_key(&key)).unwrap(), key);
        assert!(decode_key("AAAA").is_err());
        assert!(decode_key(&STANDARD.encode([1u8; 33])).is_err());
        assert!(decode_key("pas de base64 !").is_err());
    }
}
