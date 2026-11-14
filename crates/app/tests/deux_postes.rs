//! Deux postes synchronisés par le serveur « coffre » : le livrable de la
//! semaine 2 du jalon 1, vérifié de bout en bout avec la logique de
//! l'application (sessions, entrée réservée, installation depuis le serveur,
//! restauration d'une sauvegarde).
//!
//! Variables d'environnement (posées par `scripts/banc-webdav.sh`) :
//! `LGS_TEST_WEBDAV_URL`, `LGS_TEST_WEBDAV_CA`, `LGS_TEST_WEBDAV_USER`,
//! `LGS_TEST_WEBDAV_PASSWORD`. Sans elles, l'essai est ignoré, sauf si
//! `LGS_REQUIRE_WEBDAV=1`. Il provoque volontairement un refus
//! d'identifiants : ne jamais le lancer contre le serveur en service
//! (CrowdSec bannirait l'adresse).
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ligrivsstore_app::dto::{
    CreateVaultRequest, InstallRequest, KeyfileChoice, SaveEntryRequest, SyncSettingsRequest,
};
use ligrivsstore_app::{LockReason, Session, SyncOutcome};

const PASSPHRASE: &str = "lagune-pivoine-escabeau-tracteur";

struct Bench {
    server: String,
    user: String,
    password: String,
    ca: Option<Vec<u8>>,
}

fn bench() -> Option<Bench> {
    let get = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    match (
        get("LGS_TEST_WEBDAV_URL"),
        get("LGS_TEST_WEBDAV_USER"),
        get("LGS_TEST_WEBDAV_PASSWORD"),
    ) {
        (Some(folder), Some(user), Some(password)) => {
            let (scheme, rest) = folder.split_once("://").unwrap();
            let host = rest.split('/').next().unwrap();
            Some(Bench {
                server: format!("{scheme}://{host}"),
                user,
                password,
                ca: get("LGS_TEST_WEBDAV_CA").map(|path| std::fs::read(path).unwrap()),
            })
        }
        _ => {
            assert!(
                std::env::var("LGS_REQUIRE_WEBDAV").as_deref() != Ok("1"),
                "banc WebDAV exigé (LGS_REQUIRE_WEBDAV=1) mais non configuré"
            );
            eprintln!("banc WebDAV non configuré : essai ignoré");
            None
        }
    }
}

fn session(bench: &Bench, config: &Path) -> Session {
    let mut session = Session::load(config);
    session.set_root_ca(bench.ca.clone());
    session.set_calibration_target(Duration::from_millis(20));
    session
}

fn add(session: &mut Session, title: &str, password: &str) -> String {
    session
        .save_entry(SaveEntryRequest {
            id: None,
            title: title.into(),
            url: format!("https://{}.exemple", title.to_lowercase()),
            username: "hermann".into(),
            password: Some(password.into()),
            notes: String::new(),
        })
        .unwrap()
}

fn titles(session: &Session) -> Vec<String> {
    session
        .list_entries("")
        .unwrap()
        .into_iter()
        .map(|r| r.title)
        .collect()
}

fn done(outcome: SyncOutcome) -> (bool, bool, usize) {
    match outcome {
        SyncOutcome::Done {
            downloaded,
            uploaded,
            merged,
        } => (downloaded, uploaded, merged),
        other => panic!("synchronisation en échec : {other:?}"),
    }
}

#[test]
fn two_pcs_stay_in_sync_through_the_server() {
    let Some(bench) = bench() else { return };
    let dir = tempfile::tempdir().unwrap();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let file = format!("deux-postes-{}-{stamp}.kdbx", std::process::id());
    let keyfile = dir.path().join("cles").join("coffre.keyx");
    let settings = |password: Option<&str>| SyncSettingsRequest {
        server: bench.server.clone(),
        account: bench.user.clone(),
        file: file.clone(),
        password: password.map(str::to_owned),
    };

    // PC 1 : crée le coffre, règle la synchronisation, ajoute une entrée.
    let mut pc1 = session(&bench, &dir.path().join("pc1"));
    pc1.create_vault(CreateVaultRequest {
        path: dir.path().join("pc1/coffre.kdbx").display().to_string(),
        name: "Coffre d'Hermann".into(),
        passphrase: PASSPHRASE.into(),
        keyfile: KeyfileChoice::Generate {
            path: keyfile.display().to_string(),
        },
    })
    .unwrap();
    let banque = add(&mut pc1, "Banque", "banque-v1");
    pc1.configure_sync(settings(Some(&bench.password))).unwrap();
    let (_, uploaded, _) = done(pc1.sync_now());
    assert!(
        uploaded,
        "premier envoi : le coffre est créé sur le serveur"
    );

    // PC 2 : installe le coffre du serveur avec les mêmes identifiants.
    let mut pc2 = session(&bench, &dir.path().join("pc2"));
    let status = pc2
        .install_from_server(InstallRequest {
            server: bench.server.clone(),
            account: bench.user.clone(),
            file: file.clone(),
            server_password: bench.password.clone(),
            path: dir.path().join("pc2/coffre.kdbx").display().to_string(),
            passphrase: PASSPHRASE.into(),
            keyfile_path: Some(keyfile.display().to_string()),
        })
        .unwrap();
    assert!(status.unlocked);
    assert_eq!(status.entry_count, 1, "l'entrée réservée n'est pas comptée");
    assert_eq!(titles(&pc2), ["Banque"]);
    let view = pc2.sync_settings().unwrap();
    assert!(view.configured && view.has_password);
    assert_eq!(view.file, file);
    // Mêmes identifiants : l'entrée réservée n'a pas changé, rien à envoyer.
    let (_, uploaded, _) = done(pc2.sync_now());
    assert!(!uploaded);

    // Modifications des deux côtés, puis convergence.
    add(&mut pc2, "Messagerie", "messagerie-v1");
    let (_, uploaded, _) = done(pc2.sync_now());
    assert!(uploaded);
    pc1.save_entry(SaveEntryRequest {
        id: Some(banque.clone()),
        title: "Banque".into(),
        url: "https://banque.exemple".into(),
        username: "hermann".into(),
        password: Some("banque-v2".into()),
        notes: "modifiée sur le PC 1".into(),
    })
    .unwrap();
    let (downloaded, uploaded, merged) = done(pc1.sync_now());
    assert!(downloaded && uploaded && merged > 0);
    let (downloaded, _, merged) = done(pc2.sync_now());
    assert!(downloaded && merged > 0);

    for pc in [&pc1, &pc2] {
        assert_eq!(titles(pc), ["Banque", "Messagerie"]);
        assert_eq!(pc.reveal_password(&banque).unwrap().as_str(), "banque-v2");
        assert_eq!(pc.entry(&banque).unwrap().history_len, 1);
    }

    // Suppression sur le PC 2, synchronisée, puis restauration de la
    // sauvegarde la plus récente (étape S2-7 de la recette) : l'entrée
    // revient, sur les deux postes.
    let messagerie = pc2
        .list_entries("")
        .unwrap()
        .into_iter()
        .find(|row| row.title == "Messagerie")
        .unwrap()
        .id;
    pc2.delete_entry(&messagerie).unwrap();
    let (_, uploaded, _) = done(pc2.sync_now());
    assert!(uploaded);
    let newest = pc2.backups().unwrap().remove(0);
    let report = pc2.restore_backup(&newest.id).unwrap();
    assert_eq!(report.recreated, 1, "{report:?}");
    let (_, uploaded, _) = done(pc2.sync_now());
    assert!(uploaded);
    let (downloaded, _, merged) = done(pc1.sync_now());
    assert!(downloaded && merged > 0);
    for pc in [&pc1, &pc2] {
        assert_eq!(titles(pc), ["Banque", "Messagerie"]);
    }

    // Mauvais mot de passe du serveur sur le PC 1 : suspendue, sans nouvel
    // essai, puis rétablie par une nouvelle saisie.
    pc1.configure_sync(settings(Some("mauvais-mot-de-passe")))
        .unwrap();
    assert!(matches!(pc1.sync_now(), SyncOutcome::Suspended(_)));
    assert!(matches!(pc1.sync_now(), SyncOutcome::Suspended(_)));
    pc1.configure_sync(settings(Some(&bench.password))).unwrap();
    done(pc1.sync_now());

    // Le coffre verrouillé ne se synchronise pas.
    pc2.lock(LockReason::Manual);
    assert_eq!(pc2.sync_now(), SyncOutcome::Locked);
}
