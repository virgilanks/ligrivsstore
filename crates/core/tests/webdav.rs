//! Synchronisation réelle avec le serveur « coffre » (banc Apache local ou
//! serveur déployé).
//!
//! Variables d'environnement (posées par `scripts/banc-webdav.sh`) :
//! - `LGS_TEST_WEBDAV_URL` : dossier de l'utilisateur de test, par exemple
//!   `http://127.0.0.1:18081/dav/recette1/` ;
//! - `LGS_TEST_WEBDAV_USER`, `LGS_TEST_WEBDAV_PASSWORD` : son compte ;
//! - `LGS_TEST_WEBDAV_USER2`, `LGS_TEST_WEBDAV_PASSWORD2` : un second compte
//!   (cloisonnement).
//!
//! Sans ces variables, les tests sont ignorés, sauf si `LGS_REQUIRE_WEBDAV=1`.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use common::*;
use ligrivsstore_core::sync::{Fetch, Precondition, StoreOutcome, SyncError, Transport};
use ligrivsstore_core::{LocalVault, OpenLimits, SyncOptions, Vault, WebDavTransport};

struct Bench {
    folder: String,
    user: String,
    password: String,
    user2: Option<(String, String)>,
}

fn bench() -> Option<Bench> {
    let get = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    match (
        get("LGS_TEST_WEBDAV_URL"),
        get("LGS_TEST_WEBDAV_USER"),
        get("LGS_TEST_WEBDAV_PASSWORD"),
    ) {
        (Some(folder), Some(user), Some(password)) => Some(Bench {
            folder: if folder.ends_with('/') {
                folder
            } else {
                format!("{folder}/")
            },
            user,
            password,
            user2: get("LGS_TEST_WEBDAV_USER2").zip(get("LGS_TEST_WEBDAV_PASSWORD2")),
        }),
        _ => {
            assert!(
                std::env::var("LGS_REQUIRE_WEBDAV").as_deref() != Ok("1"),
                "banc WebDAV exigé (LGS_REQUIRE_WEBDAV=1) mais non configuré"
            );
            eprintln!("banc WebDAV non configuré : test ignoré");
            None
        }
    }
}

impl Bench {
    /// Adresse d'un fichier propre au test (les tests s'exécutent en parallèle).
    fn url(&self, test: &str) -> String {
        let mut bytes = [0u8; 4];
        getrandom::fill(&mut bytes).unwrap();
        format!("{}{test}-{}.kdbx", self.folder, hex::encode(bytes))
    }

    fn transport(&self, url: &str) -> WebDavTransport {
        WebDavTransport::new(url, &self.user, &self.password).unwrap()
    }
}

/// Transport qui laisse un autre terminal écrire juste avant le prochain envoi.
struct Interleaved<'a> {
    inner: &'a WebDavTransport,
    concurrent: std::cell::RefCell<Option<Vec<u8>>>,
}

impl Transport for Interleaved<'_> {
    fn fetch(&self, if_none_match: Option<&str>) -> Result<Fetch, SyncError> {
        self.inner.fetch(if_none_match)
    }

    fn store(&self, body: &[u8], precondition: &Precondition) -> Result<StoreOutcome, SyncError> {
        if let Some(other) = self.concurrent.borrow_mut().take() {
            // Écriture de l'autre terminal (le fichier du serveur date de plus
            // d'une seconde : son étiquette est forte).
            let current = match self.inner.fetch(None)? {
                Fetch::Found { etag, .. } => etag.unwrap(),
                other => panic!("{other:?}"),
            };
            assert!(!current.is_weak());
            assert_eq!(
                self.inner
                    .store(&other, &Precondition::IfMatch(current.as_str().to_owned()))?,
                StoreOutcome::Stored
            );
        }
        self.inner.store(body, precondition)
    }
}

#[test]
fn two_devices_converge_through_the_real_server() {
    let Some(bench) = bench() else { return };
    let dir = tempfile::tempdir().unwrap();
    let url = bench.url("convergence");
    let transport = bench.transport(&url);
    let options = SyncOptions::default();

    let mut a = LocalVault::create(dir.path().join("a.kdbx"), "Coffre", key(), fast_kdf()).unwrap();
    let banque = a.vault_mut().add_entry(&entry("Banque", "v1")).unwrap();
    a.save().unwrap();
    assert!(a.sync(&transport, &options).unwrap().uploaded);

    let mut b = LocalVault::clone_from_remote(
        dir.path().join("b.kdbx"),
        key(),
        OpenLimits::default(),
        &transport,
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    a.vault_mut()
        .update_entry(&banque, &entry("Banque", "modifié sur A"))
        .unwrap();
    a.save().unwrap();
    b.vault_mut()
        .add_entry(&entry("Impots", "ajouté sur B"))
        .unwrap();
    b.save().unwrap();

    a.sync(&transport, &options).unwrap();
    // B envoie juste après A : l'étiquette du serveur est faible pendant une
    // seconde ; la boucle l'attend au lieu d'échouer.
    let report = b.sync(&transport, &options).unwrap();
    assert!(report.uploaded);
    a.sync(&transport, &options).unwrap();

    for device in [&a, &b] {
        let mut names: Vec<String> = device
            .vault()
            .entries()
            .into_iter()
            .map(|e| e.title)
            .collect();
        names.sort();
        assert_eq!(names, ["Banque", "Impots"]);
        assert_eq!(
            device.vault().entry(&banque).unwrap().password.as_str(),
            "modifié sur A"
        );
    }
    eprintln!(
        "relectures pour étiquette faible côté B : {}",
        report.weak_waits
    );
}

#[test]
fn the_server_rejects_a_stale_upload_and_the_loop_recovers() {
    let Some(bench) = bench() else { return };
    let dir = tempfile::tempdir().unwrap();
    let url = bench.url("conflit");
    let transport = bench.transport(&url);
    let options = SyncOptions::default();

    let mut a = LocalVault::create(dir.path().join("a.kdbx"), "Coffre", key(), fast_kdf()).unwrap();
    a.vault_mut().add_entry(&entry("Banque", "v1")).unwrap();
    a.save().unwrap();
    a.sync(&transport, &options).unwrap();
    let mut b = LocalVault::clone_from_remote(
        dir.path().join("b.kdbx"),
        key(),
        OpenLimits::default(),
        &transport,
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1_100));

    a.vault_mut().add_entry(&entry("Messagerie", "A")).unwrap();
    a.save().unwrap();
    b.vault_mut().add_entry(&entry("Impots", "B")).unwrap();
    b.save().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1_100));

    // L'envoi de A arrive entre le téléchargement et l'envoi de B.
    let interleaved = Interleaved {
        inner: &transport,
        concurrent: std::cell::RefCell::new(Some(std::fs::read(a.path()).unwrap())),
    };
    let report = b.sync(&interleaved, &options).unwrap();
    assert!(report.conflicts >= 1, "{report:?}");
    assert!(report.uploaded);

    let remote = match transport.fetch(None).unwrap() {
        Fetch::Found { body, .. } => Vault::open(&body, &key(), &OpenLimits::default()).unwrap(),
        other => panic!("{other:?}"),
    };
    let mut names: Vec<String> = remote.entries().into_iter().map(|e| e.title).collect();
    names.sort();
    assert_eq!(names, ["Banque", "Impots", "Messagerie"]);
}

#[test]
fn creation_is_conditional_on_the_real_server() {
    let Some(bench) = bench() else { return };
    let url = bench.url("creation");
    let transport = bench.transport(&url);
    assert_eq!(
        transport
            .store(b"premier", &Precondition::IfNoneMatchAny)
            .unwrap(),
        StoreOutcome::Stored
    );
    // Un second terminal qui « crée » aussi le coffre est refusé.
    assert_eq!(
        transport
            .store(b"second", &Precondition::IfNoneMatchAny)
            .unwrap(),
        StoreOutcome::PreconditionFailed
    );
    match transport.fetch(None).unwrap() {
        Fetch::Found { body, .. } => assert_eq!(body, b"premier"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn credentials_and_isolation_are_enforced() {
    let Some(bench) = bench() else { return };
    let url = bench.url("cloisonnement");
    bench
        .transport(&url)
        .store(b"contenu", &Precondition::IfNoneMatchAny)
        .unwrap();

    let wrong = WebDavTransport::new(&url, &bench.user, "mauvais mot de passe").unwrap();
    assert!(matches!(wrong.fetch(None), Err(SyncError::Unauthorized)));

    if let Some((user2, password2)) = &bench.user2 {
        let other = WebDavTransport::new(&url, user2, password2).unwrap();
        assert!(matches!(
            other.fetch(None),
            Err(SyncError::Unauthorized | SyncError::Forbidden)
        ));
        assert!(matches!(
            other.store(b"intrusion", &Precondition::IfNoneMatchAny),
            Err(SyncError::Unauthorized | SyncError::Forbidden)
        ));
    }
}

#[test]
fn the_remote_vault_is_readable_by_keepassxc() {
    let Some(bench) = bench() else { return };
    let Some(cli) = keepassxc_cli() else { return };
    let dir = tempfile::tempdir().unwrap();
    let url = bench.url("keepassxc");
    let transport = bench.transport(&url);
    let mut a = LocalVault::create(dir.path().join("a.kdbx"), "Coffre", key(), fast_kdf()).unwrap();
    a.vault_mut()
        .add_entry(&entry("Banque", "lu-par-keepassxc"))
        .unwrap();
    a.save().unwrap();
    a.sync(&transport, &SyncOptions::default()).unwrap();

    let remote = match transport.fetch(None).unwrap() {
        Fetch::Found { body, .. } => body,
        other => panic!("{other:?}"),
    };
    let file = dir.path().join("distant.kdbx");
    std::fs::write(&file, remote).unwrap();
    let mut child = Command::new(cli)
        .args(["show", "-s", "-q"])
        .arg(&file)
        .arg("Banque")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{PASSWORD}\n").as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("lu-par-keepassxc"), "{text}");
}
