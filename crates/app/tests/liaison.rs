//! Liaison avec l'extension, de bout en bout par le canal local : appairage,
//! session chiffrée, requêtes, révocation, et refus des fautes de protocole.
//! Le client joue l'extension et le relais, avec le paquet protocol.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ligrivsstore_app::AppError;
use ligrivsstore_app::liaison::{Backend, Link, load_identity, spawn_server};
use ligrivsstore_app::navigateurs::Browsers;
use ligrivsstore_protocol::message::{decode_bytes, decode_key, encode_bytes, encode_key};
use ligrivsstore_protocol::{
    Envelope, Identity, PairState, Proximity, Request, Response, Role, Session, SiteEntry, VERSION,
    fingerprint, read_frame, write_frame,
};
use ligrivsstore_win::canal::{self, ChannelName, Stream};

const ORIGIN: &str = "chrome-extension://pbjfabapbnileccikicpifdnhkocnlbb/";

#[derive(Default)]
struct FakeBackend {
    unlocked: AtomicBool,
    shown: AtomicUsize,
    pairing_requests: AtomicUsize,
    last_url: Mutex<Option<String>>,
}

impl Backend for FakeBackend {
    fn is_unlocked(&self) -> bool {
        self.unlocked.load(Ordering::SeqCst)
    }
    fn site_entries(&self, page_url: &str) -> Result<Vec<SiteEntry>, AppError> {
        *self.last_url.lock().unwrap() = Some(page_url.to_owned());
        if !self.is_unlocked() {
            return Err(AppError::locked());
        }
        Ok(vec![SiteEntry {
            id: "e1".into(),
            title: "Banque".into(),
            username: "hermann".into(),
            proximity: Proximity::SameOrigin,
            insecure: false,
        }])
    }
    fn show(&self) {
        self.shown.fetch_add(1, Ordering::SeqCst);
    }
    fn pairing_requested(&self) {
        self.pairing_requests.fetch_add(1, Ordering::SeqCst);
    }
}

struct Bench {
    _dir: tempfile::TempDir,
    name: ChannelName,
    browsers: Arc<Browsers>,
    backend: Arc<FakeBackend>,
    app_public: [u8; 32],
}

fn bench(pairing_timeout: Duration) -> Bench {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config");
    let (identity, renewed) = load_identity(&config).unwrap();
    assert!(!renewed);
    let browsers = Arc::new(Browsers::load(&config));
    let backend = Arc::new(FakeBackend::default());
    let link = Link::new(
        identity,
        Arc::clone(&browsers),
        backend.clone() as Arc<dyn Backend>,
    )
    .with_pairing_timeout(pairing_timeout);
    let app_public = link.app_public();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let id = format!("ligrivsstore-liaison-essai-{}-{stamp}", std::process::id());
    let name = if cfg!(windows) {
        ChannelName::custom(id)
    } else {
        ChannelName::custom(
            dir.path()
                .join("canal")
                .join("canal.sock")
                .to_string_lossy(),
        )
    };
    spawn_server(&name, Arc::new(link)).unwrap();
    Bench {
        _dir: dir,
        name,
        browsers,
        backend,
        app_public,
    }
}

/// L'extension, vue de l'application, avec le relais devant elle.
struct Client {
    stream: Stream,
}

impl Client {
    fn connect(bench: &Bench, origin: &str) -> Self {
        let client = Self {
            stream: canal::connect(&bench.name).unwrap(),
        };
        client.send(&Envelope::Bridge {
            v: VERSION,
            origin: origin.into(),
        });
        client
    }

    fn send(&self, envelope: &Envelope) {
        let mut writer: &Stream = &self.stream;
        write_frame(&mut writer, &envelope.encode().unwrap()).unwrap();
    }

    fn send_raw(&self, bytes: &[u8]) {
        let mut writer: &Stream = &self.stream;
        write_frame(&mut writer, bytes).unwrap();
    }

    fn receive(&self) -> Option<Envelope> {
        let mut reader: &Stream = &self.stream;
        read_frame(&mut reader)
            .ok()
            .flatten()
            .map(|bytes| Envelope::decode(&bytes).unwrap())
    }

    fn pair(&self, identity: &Identity, browser: &str) -> (String, String) {
        self.send(&Envelope::Pair {
            v: VERSION,
            client: encode_key(&identity.public()),
            browser: browser.into(),
        });
        match self.receive() {
            Some(Envelope::PairPending { app, pairing, .. }) => (app, pairing),
            other => panic!("attendu pair-pending : {other:?}"),
        }
    }

    /// Ouvre une session ; renvoie la session et le premier message.
    fn hello(&self, identity: &Identity, app_public: &[u8; 32]) -> (Session, Response) {
        let eph = Identity::generate().unwrap();
        self.send(&Envelope::Hello {
            v: VERSION,
            client: encode_key(&identity.public()),
            eph: encode_key(&eph.public()),
        });
        match self.receive() {
            Some(Envelope::Welcome {
                eph: app_eph, n, c, ..
            }) => {
                let app_eph = decode_key(&app_eph).unwrap();
                let mut session =
                    Session::establish(Role::Client, identity, &eph, app_public, &app_eph).unwrap();
                let welcome =
                    Response::decode(&session.open(n, &decode_bytes(&c).unwrap()).unwrap())
                        .unwrap();
                (session, welcome)
            }
            other => panic!("attendu welcome : {other:?}"),
        }
    }

    fn request(&self, session: &mut Session, request: &Request) -> Option<Response> {
        let (n, sealed) = session.seal(&request.encode().unwrap()).unwrap();
        self.send(&Envelope::Msg {
            v: VERSION,
            n,
            c: encode_bytes(&sealed),
        });
        match self.receive()? {
            Envelope::Msg { n, c, .. } => Some(
                Response::decode(&session.open(n, &decode_bytes(&c).unwrap()).unwrap()).unwrap(),
            ),
            other => panic!("attendu msg : {other:?}"),
        }
    }
}

/// Confirme (ou refuse) la demande dès qu'elle apparaît dans l'application.
fn decide_when_shown(browsers: &Arc<Browsers>, confirm: bool) -> thread::JoinHandle<String> {
    let browsers = Arc::clone(browsers);
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(request) = browsers.pending().first() {
                browsers.decide(&request.id, confirm).unwrap();
                return request.fingerprint.clone();
            }
            assert!(Instant::now() < deadline, "aucune demande affichée");
            thread::sleep(Duration::from_millis(10));
        }
    })
}

fn paired(bench: &Bench) -> Identity {
    let identity = Identity::generate().unwrap();
    let client = Client::connect(bench, ORIGIN);
    let decider = decide_when_shown(&bench.browsers, true);
    client.pair(&identity, "Chrome");
    assert!(matches!(
        client.receive(),
        Some(Envelope::PairResult {
            state: PairState::Confirmed,
            ..
        })
    ));
    decider.join().unwrap();
    identity
}

#[test]
fn pairing_shows_the_same_fingerprint_on_both_sides() {
    let bench = bench(Duration::from_secs(10));
    let identity = Identity::generate().unwrap();
    let client = Client::connect(&bench, ORIGIN);
    let decider = decide_when_shown(&bench.browsers, true);
    let (app, _pairing) = client.pair(&identity, "Chrome\u{7}\u{0} pour Hermann");
    let app = decode_key(&app).unwrap();
    assert_eq!(app, bench.app_public);
    let shown_in_app = decider.join().unwrap();
    let shown_in_extension = fingerprint(&app, &identity.public());
    assert_eq!(shown_in_app, shown_in_extension);
    assert!(matches!(
        client.receive(),
        Some(Envelope::PairResult {
            state: PairState::Confirmed,
            ..
        })
    ));
    assert_eq!(bench.backend.pairing_requests.load(Ordering::SeqCst), 1);
    let listed = bench.browsers.list();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        listed[0].browser, "Chrome pour Hermann",
        "caractères de contrôle ôtés"
    );
    assert_eq!(listed[0].fingerprint, shown_in_app);
}

#[test]
fn a_refused_or_unanswered_pairing_gives_no_session() {
    let bench = bench(Duration::from_millis(300));
    let identity = Identity::generate().unwrap();
    let client = Client::connect(&bench, ORIGIN);
    let decider = decide_when_shown(&bench.browsers, false);
    client.pair(&identity, "Edge");
    assert!(matches!(
        client.receive(),
        Some(Envelope::PairResult {
            state: PairState::Refused,
            ..
        })
    ));
    decider.join().unwrap();
    // Sans réponse : expirée.
    client.pair(&identity, "Edge");
    assert!(matches!(
        client.receive(),
        Some(Envelope::PairResult {
            state: PairState::Expired,
            ..
        })
    ));
    // Aucune session pour ce navigateur.
    let eph = Identity::generate().unwrap();
    client.send(&Envelope::Hello {
        v: VERSION,
        client: encode_key(&identity.public()),
        eph: encode_key(&eph.public()),
    });
    assert!(matches!(
        client.receive(),
        Some(Envelope::Error { code, .. }) if code == "non_appaire"
    ));
    assert!(bench.browsers.list().is_empty());
}

#[test]
fn a_paired_extension_lists_the_entries_of_the_page() {
    let bench = bench(Duration::from_secs(10));
    let identity = paired(&bench);
    let client = Client::connect(&bench, ORIGIN);
    let (mut session, welcome) = client.hello(&identity, &bench.app_public);
    assert!(matches!(welcome, Response::Welcome { app, .. } if app == "ligrivsstore"));

    // Coffre verrouillé : l'extension le sait et peut montrer l'application.
    assert_eq!(
        client.request(&mut session, &Request::Status { id: 1 }),
        Some(Response::Status {
            id: 1,
            unlocked: false
        })
    );
    let url = "https://www.banque.fr/connexion".to_owned();
    match client.request(
        &mut session,
        &Request::Entries {
            id: 2,
            url: url.clone(),
        },
    ) {
        Some(Response::Error {
            id: Some(2), code, ..
        }) => assert_eq!(code, "verrouille"),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        client.request(&mut session, &Request::Show { id: 3 }),
        Some(Response::Ok { id: 3 })
    );
    assert_eq!(bench.backend.shown.load(Ordering::SeqCst), 1);

    bench.backend.unlocked.store(true, Ordering::SeqCst);
    match client.request(
        &mut session,
        &Request::Entries {
            id: 4,
            url: url.clone(),
        },
    ) {
        Some(Response::Entries { id: 4, entries }) => {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].username, "hermann");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        bench.backend.last_url.lock().unwrap().as_deref(),
        Some(url.as_str())
    );
    assert!(bench.browsers.list()[0].last_seen.is_some());
}

#[test]
fn a_revoked_browser_is_cut_off_at_the_next_message() {
    let bench = bench(Duration::from_secs(10));
    let identity = paired(&bench);
    let client = Client::connect(&bench, ORIGIN);
    let (mut session, _) = client.hello(&identity, &bench.app_public);
    let id = bench.browsers.list()[0].id.clone();
    bench.browsers.revoke(&id).unwrap();
    match client.request(&mut session, &Request::Status { id: 1 }) {
        Some(Response::Error { code, .. }) => assert_eq!(code, "non_appaire"),
        other => panic!("{other:?}"),
    }
    assert!(client.receive().is_none(), "liaison fermée");
}

#[test]
fn replayed_or_forged_messages_close_the_link() {
    let bench = bench(Duration::from_secs(10));
    let identity = paired(&bench);
    let client = Client::connect(&bench, ORIGIN);
    let (mut session, _) = client.hello(&identity, &bench.app_public);
    let (n, sealed) = session
        .seal(&Request::Status { id: 1 }.encode().unwrap())
        .unwrap();
    let message = Envelope::Msg {
        v: VERSION,
        n,
        c: encode_bytes(&sealed),
    };
    client.send(&message);
    assert!(matches!(client.receive(), Some(Envelope::Msg { .. })));
    // Le même message, rejoué : la liaison se ferme sans réponse.
    client.send(&message);
    assert!(client.receive().is_none());

    // Un intrus qui connaît la clé publique de l'extension, mais pas sa clé
    // privée, ne lit pas la réponse de l'application.
    let intruder = Identity::generate().unwrap();
    let client = Client::connect(&bench, ORIGIN);
    let eph = Identity::generate().unwrap();
    client.send(&Envelope::Hello {
        v: VERSION,
        client: encode_key(&identity.public()),
        eph: encode_key(&eph.public()),
    });
    let Some(Envelope::Welcome {
        eph: app_eph, n, c, ..
    }) = client.receive()
    else {
        panic!("welcome attendu");
    };
    let mut fake = Session::establish(
        Role::Client,
        &intruder,
        &eph,
        &bench.app_public,
        &decode_key(&app_eph).unwrap(),
    )
    .unwrap();
    assert!(fake.open(n, &decode_bytes(&c).unwrap()).is_err());
    // Et ce qu'il envoie est refusé : la liaison se ferme.
    let (n, sealed) = fake.seal(br#"{"op":"status","id":1}"#).unwrap();
    client.send(&Envelope::Msg {
        v: VERSION,
        n,
        c: encode_bytes(&sealed),
    });
    assert!(client.receive().is_none());
}

#[test]
fn unknown_extensions_and_links_without_relay_are_refused() {
    let bench = bench(Duration::from_secs(10));
    let client = Client::connect(
        &bench,
        "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
    );
    assert!(matches!(
        client.receive(),
        Some(Envelope::Error { code, .. }) if code == "origine_refusee"
    ));
    assert!(client.receive().is_none());

    // Sans annonce du relais.
    let raw = canal::connect(&bench.name).unwrap();
    let client = Client { stream: raw };
    client.send(&Envelope::Pair {
        v: VERSION,
        client: encode_key(&[7u8; 32]),
        browser: "Chrome".into(),
    });
    assert!(matches!(
        client.receive(),
        Some(Envelope::Error { code, .. }) if code == "message_invalide"
    ));

    // Version inconnue ou message illisible : liaison fermée.
    let client = Client::connect(&bench, ORIGIN);
    client.send_raw(br#"{"type":"hello","v":2,"client":"a","eph":"b"}"#);
    assert!(client.receive().is_none());
    assert_eq!(bench.backend.pairing_requests.load(Ordering::SeqCst), 0);
}

#[test]
fn the_app_key_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (first, renewed) = load_identity(dir.path()).unwrap();
    assert!(!renewed);
    let (second, renewed) = load_identity(dir.path()).unwrap();
    assert!(!renewed);
    assert_eq!(first.public(), second.public());
    // Fichier abîmé : nouvelle clé, signalée.
    std::fs::write(
        dir.path().join(ligrivsstore_app::liaison::KEY_FILE),
        b"abime",
    )
    .unwrap();
    let (third, renewed) = load_identity(dir.path()).unwrap();
    assert!(renewed);
    assert_ne!(third.public(), first.public());
}
