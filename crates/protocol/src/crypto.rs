//! Clés, empreinte d'appairage et chiffrement des messages.
//!
//! **Appairage** (une fois par navigateur) : l'extension et l'application
//! échangent leurs clés publiques X25519 permanentes. Chacune affiche
//! l'[empreinte](fingerprint) des deux clés, six groupes de cinq chiffres ;
//! l'utilisateur les compare et confirme des deux côtés.
//!
//! **Session** (à chaque liaison) : chaque partie tire aussi une clé
//! éphémère. Les clés de session viennent de HKDF-SHA256 appliqué aux deux
//! échanges Diffie-Hellman, permanent-permanent (qui authentifie les deux
//! parties appairées) et éphémère-éphémère (qui rend chaque session unique
//! et protège les sessions passées si une clé permanente fuit un jour). Le
//! sel et l'information de HKDF lient les quatre clés publiques.
//!
//! **Messages** : AES-256-GCM, une clé par sens. Le nonce porte le sens et un
//! compteur ; le compteur reçu doit être exactement le suivant, ce qui écarte
//! tout message rejoué, supprimé ou réordonné.

use std::fmt;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::ProtocolError;

/// Taille d'une clé X25519 (publique ou privée) et d'une clé AES-256.
pub const KEY_LEN: usize = 32;

/// Nombre de messages par sens dans une session : au-delà, il faut rouvrir
/// la liaison. Les compteurs restent ainsi des entiers exacts en JavaScript.
pub const MAX_MESSAGES: u64 = 1 << 32;

const FINGERPRINT_LABEL: &[u8] = b"ligrivsstore/empreinte/v1";
const HKDF_SALT: &[u8] = b"ligrivsstore/protocole/v1";
const HKDF_INFO: &[u8] = b"ligrivsstore/session/v1";
const AAD: &[u8] = b"ligrivsstore/v1";
const CLIENT_TO_APP: u8 = 1;
const APP_TO_CLIENT: u8 = 2;

/// Paire de clés X25519 (permanente ou éphémère).
pub struct Identity {
    secret: StaticSecret,
    public: PublicKey,
}

impl Identity {
    /// Tire une nouvelle paire de clés avec l'aléa du système.
    pub fn generate() -> Result<Self, ProtocolError> {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::fill(bytes.as_mut()).map_err(|_| ProtocolError::Random)?;
        Ok(Self::from_secret(*bytes))
    }

    /// Paire de clés à partir de la clé privée (relue après stockage).
    pub fn from_secret(bytes: [u8; KEY_LEN]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Clé privée, pour la conserver protégée (DPAPI sous Windows).
    pub fn secret_bytes(&self) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    /// Clé publique.
    pub fn public(&self) -> [u8; KEY_LEN] {
        self.public.to_bytes()
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("public", &hex_prefix(&self.public()))
            .field("secret", &"<masquée>")
            .finish()
    }
}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// Empreinte d'appairage : SHA-256 d'un libellé et des deux clés publiques
/// (application, puis extension), lue en six groupes de cinq chiffres.
/// Chaque groupe vient de cinq octets, pris comme un entier modulo 100 000.
pub fn fingerprint(app_public: &[u8; KEY_LEN], client_public: &[u8; KEY_LEN]) -> String {
    let digest = Sha256::new()
        .chain_update(FINGERPRINT_LABEL)
        .chain_update(app_public)
        .chain_update(client_public)
        .finalize();
    digest
        .chunks(5)
        .take(6)
        .map(|chunk| {
            let value = chunk
                .iter()
                .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
            format!("{:05}", value % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Côté de la liaison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// L'extension, qui ouvre la session.
    Client,
    /// L'application.
    App,
}

/// Session chiffrée : une clé et un compteur par sens.
pub struct Session {
    send: Aes256Gcm,
    receive: Aes256Gcm,
    send_direction: u8,
    receive_direction: u8,
    sent: u64,
    received: u64,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("sent", &self.sent)
            .field("received", &self.received)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Établit la session à partir des clés permanentes et éphémères des deux
    /// parties.
    pub fn establish(
        role: Role,
        own_static: &Identity,
        own_ephemeral: &Identity,
        peer_static: &[u8; KEY_LEN],
        peer_ephemeral: &[u8; KEY_LEN],
    ) -> Result<Self, ProtocolError> {
        let (client_to_app, app_to_client) =
            derive_keys(role, own_static, own_ephemeral, peer_static, peer_ephemeral)?;
        let client_to_app =
            Aes256Gcm::new_from_slice(client_to_app.as_ref()).map_err(|_| ProtocolError::BadKey)?;
        let app_to_client =
            Aes256Gcm::new_from_slice(app_to_client.as_ref()).map_err(|_| ProtocolError::BadKey)?;
        Ok(match role {
            Role::Client => Self {
                send: client_to_app,
                receive: app_to_client,
                send_direction: CLIENT_TO_APP,
                receive_direction: APP_TO_CLIENT,
                sent: 0,
                received: 0,
            },
            Role::App => Self {
                send: app_to_client,
                receive: client_to_app,
                send_direction: APP_TO_CLIENT,
                receive_direction: CLIENT_TO_APP,
                sent: 0,
                received: 0,
            },
        })
    }

    /// Chiffre un message ; renvoie son compteur et le chiffré (étiquette
    /// d'authentification comprise).
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<(u64, Vec<u8>), ProtocolError> {
        if self.sent >= MAX_MESSAGES {
            return Err(ProtocolError::Exhausted);
        }
        let counter = self.sent;
        let nonce = nonce(self.send_direction, counter);
        let ciphertext = self
            .send
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: plaintext,
                    aad: AAD,
                },
            )
            .map_err(|_| ProtocolError::Tampered)?;
        self.sent += 1;
        Ok((counter, ciphertext))
    }

    /// Déchiffre le message suivant. Le compteur doit être exactement celui
    /// attendu : un message rejoué, perdu ou réordonné est refusé.
    pub fn open(&mut self, counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        if counter != self.received {
            return Err(ProtocolError::Replay {
                expected: self.received,
                got: counter,
            });
        }
        if counter >= MAX_MESSAGES {
            return Err(ProtocolError::Exhausted);
        }
        let nonce = nonce(self.receive_direction, counter);
        let plaintext = self
            .receive
            .decrypt(
                &nonce.into(),
                Payload {
                    msg: ciphertext,
                    aad: AAD,
                },
            )
            .map_err(|_| ProtocolError::Tampered)?;
        self.received += 1;
        Ok(plaintext)
    }
}

/// Nonce de 12 octets : trois octets nuls, le sens, puis le compteur sur
/// 8 octets, poids fort en tête.
fn nonce(direction: u8, counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    if let Some(slot) = nonce.get_mut(3) {
        *slot = direction;
    }
    for (slot, byte) in nonce.iter_mut().skip(4).zip(counter.to_be_bytes()) {
        *slot = byte;
    }
    nonce
}

type KeyPair = (Zeroizing<[u8; KEY_LEN]>, Zeroizing<[u8; KEY_LEN]>);

/// Clés de session (extension → application, application → extension).
fn derive_keys(
    role: Role,
    own_static: &Identity,
    own_ephemeral: &Identity,
    peer_static: &[u8; KEY_LEN],
    peer_ephemeral: &[u8; KEY_LEN],
) -> Result<KeyPair, ProtocolError> {
    let static_shared = own_static
        .secret
        .diffie_hellman(&PublicKey::from(*peer_static));
    let ephemeral_shared = own_ephemeral
        .secret
        .diffie_hellman(&PublicKey::from(*peer_ephemeral));
    if !static_shared.was_contributory() || !ephemeral_shared.was_contributory() {
        return Err(ProtocolError::BadKey);
    }
    let (client_static, app_static, client_ephemeral, app_ephemeral) = match role {
        Role::Client => (
            own_static.public(),
            *peer_static,
            own_ephemeral.public(),
            *peer_ephemeral,
        ),
        Role::App => (
            *peer_static,
            own_static.public(),
            *peer_ephemeral,
            own_ephemeral.public(),
        ),
    };
    let mut ikm = Zeroizing::new(Vec::with_capacity(2 * KEY_LEN));
    ikm.extend_from_slice(static_shared.as_bytes());
    ikm.extend_from_slice(ephemeral_shared.as_bytes());
    let mut info = Vec::with_capacity(HKDF_INFO.len() + 4 * KEY_LEN);
    info.extend_from_slice(HKDF_INFO);
    for key in [client_static, app_static, client_ephemeral, app_ephemeral] {
        info.extend_from_slice(&key);
    }
    let mut okm = Zeroizing::new([0u8; 2 * KEY_LEN]);
    Hkdf::<Sha256>::new(Some(HKDF_SALT), ikm.as_slice())
        .expand(&info, okm.as_mut())
        .map_err(|_| ProtocolError::BadKey)?;
    let (first, second) = okm.split_at(KEY_LEN);
    let client_to_app = <[u8; KEY_LEN]>::try_from(first).map_err(|_| ProtocolError::BadKey)?;
    let app_to_client = <[u8; KEY_LEN]>::try_from(second).map_err(|_| ProtocolError::BadKey)?;
    Ok((Zeroizing::new(client_to_app), Zeroizing::new(app_to_client)))
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde_json::{Value, json};

    use super::*;

    fn pair() -> (Identity, Identity, Identity, Identity) {
        (
            Identity::generate().unwrap(),
            Identity::generate().unwrap(),
            Identity::generate().unwrap(),
            Identity::generate().unwrap(),
        )
    }

    fn sessions() -> (Session, Session) {
        let (client, app, client_eph, app_eph) = pair();
        let client_session = Session::establish(
            Role::Client,
            &client,
            &client_eph,
            &app.public(),
            &app_eph.public(),
        )
        .unwrap();
        let app_session = Session::establish(
            Role::App,
            &app,
            &app_eph,
            &client.public(),
            &client_eph.public(),
        )
        .unwrap();
        (client_session, app_session)
    }

    #[test]
    fn both_sides_agree_and_messages_flow_both_ways() {
        let (mut client, mut app) = sessions();
        for round in 0..3u64 {
            let (n, sealed) = client.seal(format!("requête {round}").as_bytes()).unwrap();
            assert_eq!(n, round);
            assert_eq!(
                app.open(n, &sealed).unwrap(),
                format!("requête {round}").as_bytes()
            );
            let (n, sealed) = app.seal(b"reponse").unwrap();
            assert_eq!(client.open(n, &sealed).unwrap(), b"reponse");
        }
    }

    #[test]
    fn replayed_reordered_or_dropped_messages_are_refused() {
        let (mut client, mut app) = sessions();
        let (n0, first) = client.seal(b"un").unwrap();
        let (n1, second) = client.seal(b"deux").unwrap();
        // Réordonné : le second avant le premier.
        assert!(matches!(
            app.open(n1, &second),
            Err(ProtocolError::Replay {
                expected: 0,
                got: 1
            })
        ));
        // Compteur falsifié pour faire passer le second en premier.
        assert!(matches!(
            app.open(n0, &second),
            Err(ProtocolError::Tampered)
        ));
        app.open(n0, &first).unwrap();
        // Rejoué.
        assert!(matches!(
            app.open(n0, &first),
            Err(ProtocolError::Replay {
                expected: 1,
                got: 0
            })
        ));
        app.open(n1, &second).unwrap();
    }

    #[test]
    fn altered_truncated_or_reflected_messages_are_refused() {
        let (mut client, mut app) = sessions();
        let (n, sealed) = client.seal(b"secret").unwrap();
        for index in 0..sealed.len() {
            let mut altered = sealed.clone();
            altered[index] ^= 0x01;
            assert!(matches!(
                app.open(n, &altered),
                Err(ProtocolError::Tampered)
            ));
        }
        assert!(matches!(
            app.open(n, &sealed[..sealed.len() - 1]),
            Err(ProtocolError::Tampered)
        ));
        assert!(matches!(app.open(n, &[]), Err(ProtocolError::Tampered)));
        // Renvoyé à son auteur : l'autre sens a une autre clé.
        assert!(matches!(
            client.open(n, &sealed),
            Err(ProtocolError::Tampered)
        ));
        app.open(n, &sealed).unwrap();
    }

    #[test]
    fn a_session_with_other_keys_cannot_read() {
        let (client, app, client_eph, app_eph) = pair();
        let intruder = Identity::generate().unwrap();
        let mut genuine = Session::establish(
            Role::Client,
            &client,
            &client_eph,
            &app.public(),
            &app_eph.public(),
        )
        .unwrap();
        // L'intrus se fait passer pour l'application, sans sa clé privée.
        let mut fake = Session::establish(
            Role::App,
            &intruder,
            &app_eph,
            &client.public(),
            &client_eph.public(),
        )
        .unwrap();
        let (n, sealed) = genuine.seal(b"liste").unwrap();
        assert!(matches!(
            fake.open(n, &sealed),
            Err(ProtocolError::Tampered)
        ));
        // Deux sessions des mêmes parties, éphémères différentes : clés différentes.
        let other_eph = Identity::generate().unwrap();
        let mut other = Session::establish(
            Role::App,
            &app,
            &other_eph,
            &client.public(),
            &client_eph.public(),
        )
        .unwrap();
        assert!(matches!(
            other.open(n, &sealed),
            Err(ProtocolError::Tampered)
        ));
    }

    #[test]
    fn low_order_public_keys_are_refused() {
        let (client, _, client_eph, _) = pair();
        let zero = [0u8; KEY_LEN];
        let mut one = [0u8; KEY_LEN];
        one[0] = 1;
        for bad in [zero, one] {
            assert!(matches!(
                Session::establish(Role::Client, &client, &client_eph, &bad, &bad),
                Err(ProtocolError::BadKey)
            ));
        }
    }

    #[test]
    fn fingerprint_has_six_groups_and_depends_on_both_keys() {
        let (client, app, other, _) = pair();
        let shown = fingerprint(&app.public(), &client.public());
        let groups: Vec<&str> = shown.split(' ').collect();
        assert_eq!(groups.len(), 6);
        assert!(
            groups
                .iter()
                .all(|g| g.len() == 5 && g.bytes().all(|b| b.is_ascii_digit()))
        );
        assert_ne!(shown, fingerprint(&app.public(), &other.public()));
        assert_ne!(
            shown,
            fingerprint(&client.public(), &app.public()),
            "ordre fixé"
        );
    }

    #[test]
    fn the_secret_key_never_shows_in_debug_output() {
        let identity = Identity::from_secret([7u8; KEY_LEN]);
        let shown = format!("{identity:?}");
        assert!(shown.contains("<masquée>"));
        assert!(!shown.contains("0707070707"));
    }

    // --- Vecteurs d'essai communs avec l'extension (TypeScript, Web Crypto).

    const VECTORS: &str = include_str!("../tests/vecteurs.json");

    fn b64(bytes: &[u8]) -> String {
        STANDARD.encode(bytes)
    }

    fn key(value: &Value, name: &str) -> [u8; KEY_LEN] {
        let text = value[name]
            .as_str()
            .unwrap_or_else(|| panic!("{name} absent"));
        STANDARD.decode(text).unwrap().try_into().unwrap()
    }

    /// Clés privées des vecteurs : octets fixes, publics, réservés aux essais.
    fn vector_identities() -> (Identity, Identity, Identity, Identity) {
        let pattern = |start: u8| {
            let mut bytes = [0u8; KEY_LEN];
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = start.wrapping_add(index as u8);
            }
            Identity::from_secret(bytes)
        };
        (pattern(0x10), pattern(0x40), pattern(0x70), pattern(0xa0))
    }

    fn compute_vectors() -> Value {
        let (client, app, client_eph, app_eph) = vector_identities();
        let (client_to_app, app_to_client) = derive_keys(
            Role::Client,
            &client,
            &client_eph,
            &app.public(),
            &app_eph.public(),
        )
        .unwrap();
        let mut client_session = Session::establish(
            Role::Client,
            &client,
            &client_eph,
            &app.public(),
            &app_eph.public(),
        )
        .unwrap();
        let mut app_session = Session::establish(
            Role::App,
            &app,
            &app_eph,
            &client.public(),
            &client_eph.public(),
        )
        .unwrap();
        let exchanges = [
            (
                "app-vers-extension",
                r#"{"op":"welcome","app":"ligrivsstore","version":"0.1.0"}"#,
            ),
            (
                "extension-vers-app",
                r#"{"op":"entries","id":1,"url":"https://www.banque.fr/connexion"}"#,
            ),
            (
                "app-vers-extension",
                r#"{"op":"entries","id":1,"entries":[{"id":"e1","title":"Banque","username":"hermann","proximity":"same-origin","insecure":false}]}"#,
            ),
            ("extension-vers-app", r#"{"op":"status","id":2}"#),
            ("extension-vers-app", ""),
        ];
        let messages: Vec<Value> = exchanges
            .iter()
            .map(|(direction, text)| {
                let (n, sealed) = if *direction == "extension-vers-app" {
                    client_session.seal(text.as_bytes()).unwrap()
                } else {
                    app_session.seal(text.as_bytes()).unwrap()
                };
                json!({ "direction": direction, "n": n, "plaintext": text, "ciphertext": b64(&sealed) })
            })
            .collect();
        json!({
            "description": "Vecteurs d'essai du protocole ligrivsstore v1 (crates/protocol/src/crypto.rs). Clés réservées aux essais.",
            "client_static_secret": b64(client.secret_bytes().as_ref()),
            "client_static_public": b64(&client.public()),
            "app_static_secret": b64(app.secret_bytes().as_ref()),
            "app_static_public": b64(&app.public()),
            "client_ephemeral_secret": b64(client_eph.secret_bytes().as_ref()),
            "client_ephemeral_public": b64(&client_eph.public()),
            "app_ephemeral_secret": b64(app_eph.secret_bytes().as_ref()),
            "app_ephemeral_public": b64(&app_eph.public()),
            "fingerprint": fingerprint(&app.public(), &client.public()),
            "key_client_to_app": b64(client_to_app.as_ref()),
            "key_app_to_client": b64(app_to_client.as_ref()),
            "messages": messages,
        })
    }

    #[test]
    fn vectors_match_the_shared_file() {
        let expected: Value = serde_json::from_str(VECTORS).unwrap();
        assert_eq!(compute_vectors(), expected, "vecteurs à régénérer ?");
        // Et le fichier se relit par l'autre côté : l'application déchiffre ce
        // que l'extension a chiffré, et inversement.
        let (client, app, client_eph, app_eph) = vector_identities();
        assert_eq!(key(&expected, "app_static_public"), app.public());
        let mut app_session = Session::establish(
            Role::App,
            &app,
            &app_eph,
            &client.public(),
            &client_eph.public(),
        )
        .unwrap();
        let mut client_session = Session::establish(
            Role::Client,
            &client,
            &client_eph,
            &app.public(),
            &app_eph.public(),
        )
        .unwrap();
        for message in expected["messages"].as_array().unwrap() {
            let n = message["n"].as_u64().unwrap();
            let sealed = STANDARD
                .decode(message["ciphertext"].as_str().unwrap())
                .unwrap();
            let opened = if message["direction"] == "extension-vers-app" {
                app_session.open(n, &sealed).unwrap()
            } else {
                client_session.open(n, &sealed).unwrap()
            };
            assert_eq!(opened, message["plaintext"].as_str().unwrap().as_bytes());
        }
    }

    /// Régénère le fichier : `cargo test -p ligrivsstore-protocol -- --ignored`.
    #[test]
    #[ignore = "régénère tests/vecteurs.json"]
    fn regenerate_vectors() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vecteurs.json");
        let text = serde_json::to_string_pretty(&compute_vectors()).unwrap();
        std::fs::write(path, text + "\n").unwrap();
    }
}
