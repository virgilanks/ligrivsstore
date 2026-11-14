//! Liaison avec l'extension de navigateur (note de conception n° 3, sections
//! 6.1 et 6.2 ; décision 0012).
//!
//! L'application ouvre le canal nommé de son compte ; le relais
//! `ligrivsstore-pont` le rejoint pour chaque liaison ouverte par
//! l'extension. Sur chaque liaison :
//!
//! 1. le relais annonce l'origine de l'extension (tenue du navigateur) :
//!    seules les extensions admises passent ;
//! 2. **appairage** (une fois par navigateur) : l'extension envoie sa clé
//!    publique ; l'application affiche l'empreinte et attend la décision de
//!    l'utilisateur ;
//! 3. **session** : l'extension appairée envoie sa clé permanente et une clé
//!    éphémère ; l'application répond par la sienne et un premier message
//!    chiffré, puis répond aux requêtes chiffrées.
//!
//! L'application ne répond qu'avec ce que l'extension affiche : titres,
//! identifiants et proximité des entrées de la page, jamais de mot de passe
//! (le remplissage arrive en semaine 4).

use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use ligrivsstore_protocol::crypto::KEY_LEN;
use ligrivsstore_protocol::message::{decode_bytes, decode_key, encode_bytes, encode_key};
use ligrivsstore_protocol::{
    Envelope, Identity, ProtocolError, Request, Response, Role, Session, SiteEntry, VERSION,
    extension_origin_allowed, fingerprint, read_frame, write_frame,
};
use ligrivsstore_win::canal::{self, ChannelName, Stream};

use crate::error::AppError;
use crate::navigateurs::{Browsers, PAIRING_TIMEOUT};

/// Fichier de la clé privée de l'application, dans le dossier des réglages.
pub const KEY_FILE: &str = "cle-appairage.bin";

/// Liaisons ouvertes en même temps, au plus.
pub const MAX_CONNECTIONS: usize = 8;

/// Longueur maximale d'une adresse de page.
pub const MAX_URL: usize = 8 * 1024;

/// Ce que la liaison demande au reste de l'application.
pub trait Backend: Send + Sync {
    /// Le coffre est-il déverrouillé ?
    fn is_unlocked(&self) -> bool;
    /// Entrées qui correspondent à la page (erreur `verrouille` si le coffre
    /// est verrouillé).
    fn site_entries(&self, page_url: &str) -> Result<Vec<SiteEntry>, AppError>;
    /// Montrer la fenêtre de l'application.
    fn show(&self);
    /// Une demande d'appairage attend la décision de l'utilisateur.
    fn pairing_requested(&self);
}

/// Clé permanente de l'application : relue, ou créée au premier lancement.
/// Sous Windows, elle est protégée par DPAPI (liée au compte Windows) ;
/// ailleurs (développement, essais), gardée dans un fichier en 0600.
///
/// Renvoie aussi `true` si une nouvelle clé a remplacé une clé illisible :
/// les navigateurs appairés ne peuvent plus ouvrir de session et doivent être
/// oubliés.
pub fn load_identity(config_dir: &Path) -> Result<(Identity, bool), AppError> {
    let path = config_dir.join(KEY_FILE);
    match std::fs::read(&path) {
        Ok(stored) => match read_secret(&stored) {
            Some(identity) => Ok((identity, false)),
            None => Ok((create_identity(&path)?, true)),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok((create_identity(&path)?, false))
        }
        Err(error) => Err(AppError::internal(error)),
    }
}

fn read_secret(stored: &[u8]) -> Option<Identity> {
    let secret = if cfg!(windows) {
        ligrivsstore_win::unprotect_secret(stored).ok()?
    } else {
        zeroize::Zeroizing::new(stored.to_vec())
    };
    let bytes = <[u8; KEY_LEN]>::try_from(secret.as_slice()).ok()?;
    Some(Identity::from_secret(bytes))
}

fn create_identity(path: &Path) -> Result<Identity, AppError> {
    let identity = Identity::generate().map_err(AppError::internal)?;
    let secret = identity.secret_bytes();
    let stored = if cfg!(windows) {
        ligrivsstore_win::protect_secret(secret.as_ref(), "ligrivsstore : clé d'appairage")
            .map_err(AppError::internal)?
    } else {
        secret.to_vec()
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(AppError::internal)?;
    }
    ligrivsstore_core::storage::replace_file(path, &stored)?;
    Ok(identity)
}

/// La liaison : clé de l'application, registre des navigateurs et accès au
/// reste de l'application.
pub struct Link {
    identity: Identity,
    browsers: Arc<Browsers>,
    backend: Arc<dyn Backend>,
    pairing_timeout: Duration,
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

/// Lecteur et écrivain d'une même liaison.
type Duplex<'a, S> = (&'a S, &'a S);

impl Link {
    /// Prépare la liaison.
    pub fn new(identity: Identity, browsers: Arc<Browsers>, backend: Arc<dyn Backend>) -> Self {
        Self {
            identity,
            browsers,
            backend,
            pairing_timeout: PAIRING_TIMEOUT,
        }
    }

    /// Délai de décision d'un appairage (essais).
    pub fn with_pairing_timeout(mut self, timeout: Duration) -> Self {
        self.pairing_timeout = timeout;
        self
    }

    /// Clé publique permanente de l'application.
    pub fn app_public(&self) -> [u8; KEY_LEN] {
        self.identity.public()
    }

    /// Sert une liaison jusqu'à sa fermeture, ou jusqu'à la première faute
    /// de protocole (message altéré, rejoué, hors séquence…).
    pub fn serve<S>(&self, stream: &S) -> Result<(), ProtocolError>
    where
        for<'a> &'a S: Read + Write,
    {
        let duplex: Duplex<'_, S> = (stream, stream);
        let origin = match read_envelope(duplex)? {
            Some(Envelope::Bridge { origin, .. }) => origin,
            Some(_) => return refuse(duplex, "message_invalide", "liaison sans relais"),
            None => return Ok(()),
        };
        if !extension_origin_allowed(&origin) {
            return refuse(duplex, "origine_refusee", "extension non reconnue");
        }
        loop {
            match read_envelope(duplex)? {
                None => return Ok(()),
                Some(Envelope::Pair {
                    client, browser, ..
                }) => self.pair(duplex, &origin, &client, &browser)?,
                Some(Envelope::Hello { client, eph, .. }) => {
                    return self.session(duplex, &origin, &client, &eph);
                }
                Some(_) => return refuse(duplex, "message_invalide", "message inattendu"),
            }
        }
    }

    fn pair<S>(
        &self,
        duplex: Duplex<'_, S>,
        origin: &str,
        client: &str,
        browser: &str,
    ) -> Result<(), ProtocolError>
    where
        for<'a> &'a S: Read + Write,
    {
        let client_key = match decode_key(client) {
            Ok(key) => key,
            Err(_) => return refuse(duplex, "cle_refusee", "clé de l'extension illisible"),
        };
        let shown = fingerprint(&self.identity.public(), &client_key);
        let browser = browser_name(browser);
        let id = match self.browsers.request(&browser, origin, client, &shown) {
            Ok(id) => id,
            Err(error) => return refuse(duplex, error.code, &error.message),
        };
        send(
            duplex,
            &Envelope::PairPending {
                v: VERSION,
                app: encode_key(&self.identity.public()),
                pairing: id.clone(),
            },
        )?;
        self.backend.pairing_requested();
        let state = self.browsers.wait_decision(&id, self.pairing_timeout);
        send(
            duplex,
            &Envelope::PairResult {
                v: VERSION,
                pairing: id,
                state,
            },
        )
    }

    fn session<S>(
        &self,
        duplex: Duplex<'_, S>,
        origin: &str,
        client: &str,
        eph: &str,
    ) -> Result<(), ProtocolError>
    where
        for<'a> &'a S: Read + Write,
    {
        let Some(paired) = self.browsers.find(client, origin) else {
            return refuse(
                duplex,
                "non_appaire",
                "navigateur non appairé : appairez-le depuis les options de l'extension",
            );
        };
        let (client_key, eph_key) = match (decode_key(client), decode_key(eph)) {
            (Ok(c), Ok(e)) => (c, e),
            _ => return refuse(duplex, "cle_refusee", "clé illisible"),
        };
        // Clé éphémère : sa partie privée disparaît dès la session établie.
        let own_eph = Identity::generate()?;
        let own_eph_public = own_eph.public();
        let mut session =
            match Session::establish(Role::App, &self.identity, &own_eph, &client_key, &eph_key) {
                Ok(session) => session,
                Err(_) => return refuse(duplex, "cle_refusee", "clé refusée"),
            };
        drop(own_eph);
        self.browsers.touch(&paired.id);
        let welcome = Response::Welcome {
            app: "ligrivsstore".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        };
        let (n, sealed) = session.seal(&welcome.encode()?)?;
        send(
            duplex,
            &Envelope::Welcome {
                v: VERSION,
                eph: encode_key(&own_eph_public),
                n,
                c: encode_bytes(&sealed),
            },
        )?;
        loop {
            let (n, c) = match read_envelope(duplex)? {
                None => return Ok(()),
                Some(Envelope::Msg { n, c, .. }) => (n, c),
                Some(_) => return Ok(()),
            };
            let plaintext = session.open(n, &decode_bytes(&c)?)?;
            let response = if !self.browsers.is_paired(&paired.id) {
                let refused = Response::Error {
                    id: None,
                    code: "non_appaire".into(),
                    message: "ce navigateur a été révoqué dans l'application".into(),
                };
                let (n, sealed) = session.seal(&refused.encode()?)?;
                return send(
                    duplex,
                    &Envelope::Msg {
                        v: VERSION,
                        n,
                        c: encode_bytes(&sealed),
                    },
                );
            } else {
                match Request::decode(&plaintext) {
                    Ok(request) => self.handle(request),
                    Err(_) => Response::Error {
                        id: None,
                        code: "requete_invalide".into(),
                        message: "requête inconnue".into(),
                    },
                }
            };
            let (n, sealed) = session.seal(&response.encode()?)?;
            send(
                duplex,
                &Envelope::Msg {
                    v: VERSION,
                    n,
                    c: encode_bytes(&sealed),
                },
            )?;
        }
    }

    fn handle(&self, request: Request) -> Response {
        match request {
            Request::Status { id } => Response::Status {
                id,
                unlocked: self.backend.is_unlocked(),
            },
            Request::Entries { id, url } => {
                if url.len() > MAX_URL {
                    return Response::Error {
                        id: Some(id),
                        code: "requete_invalide".into(),
                        message: "adresse trop longue".into(),
                    };
                }
                match self.backend.site_entries(&url) {
                    Ok(entries) => Response::Entries { id, entries },
                    Err(error) => Response::Error {
                        id: Some(id),
                        code: error.code.into(),
                        message: error.message,
                    },
                }
            }
            Request::Show { id } => {
                self.backend.show();
                Response::Ok { id }
            }
        }
    }
}

/// Nom du navigateur, tel que l'extension le donne : 40 caractères
/// imprimables au plus.
fn browser_name(raw: &str) -> String {
    let name: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(40)
        .collect::<String>()
        .trim()
        .to_owned();
    if name.is_empty() {
        "Navigateur".into()
    } else {
        name
    }
}

fn read_envelope<S>(duplex: Duplex<'_, S>) -> Result<Option<Envelope>, ProtocolError>
where
    for<'a> &'a S: Read + Write,
{
    let mut reader = duplex.0;
    match read_frame(&mut reader)? {
        None => Ok(None),
        Some(bytes) => Envelope::decode(&bytes).map(Some),
    }
}

fn send<S>(duplex: Duplex<'_, S>, envelope: &Envelope) -> Result<(), ProtocolError>
where
    for<'a> &'a S: Read + Write,
{
    let mut writer = duplex.1;
    write_frame(&mut writer, &envelope.encode()?)
}

fn refuse<S>(duplex: Duplex<'_, S>, code: &str, message: &str) -> Result<(), ProtocolError>
where
    for<'a> &'a S: Read + Write,
{
    send(duplex, &Envelope::error(code, message))
}

/// Ouvre le canal et sert chaque liaison sur un fil à part.
pub fn spawn_server(name: &ChannelName, link: Arc<Link>) -> Result<(), AppError> {
    let listener = canal::listen(name).map_err(AppError::internal)?;
    let open = Arc::new(AtomicUsize::new(0));
    thread::Builder::new()
        .name("ligrivsstore-liaison".into())
        .spawn(move || {
            loop {
                let stream = match listener.accept() {
                    Ok(stream) => stream,
                    Err(_) => {
                        thread::sleep(Duration::from_millis(200));
                        continue;
                    }
                };
                if open.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                    drop(stream);
                    continue;
                }
                open.fetch_add(1, Ordering::SeqCst);
                let (link, counter) = (Arc::clone(&link), Arc::clone(&open));
                let spawned = thread::Builder::new()
                    .name("ligrivsstore-liaison-session".into())
                    .spawn(move || {
                        let stream: Stream = stream;
                        let _ = link.serve(&stream);
                        counter.fetch_sub(1, Ordering::SeqCst);
                    });
                if spawned.is_err() {
                    // La liaison n'a pas démarré : elle ne compte pas.
                    open.fetch_sub(1, Ordering::SeqCst);
                }
            }
        })
        .map_err(AppError::internal)?;
    Ok(())
}
