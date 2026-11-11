//! Boucle de synchronisation, avec un serveur simulé en mémoire.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

use common::*;
use ligrivsstore_core::sync::SyncError;
use ligrivsstore_core::{Error, LocalVault, OpenLimits, SyncOptions, Vault, VaultKey};

fn options() -> SyncOptions {
    SyncOptions {
        weak_etag_wait: Duration::from_millis(5),
        ..SyncOptions::default()
    }
}

fn titles(local: &LocalVault) -> Vec<String> {
    local
        .vault()
        .entries()
        .into_iter()
        .map(|e| e.title)
        .collect()
}

/// Terminal A crée le coffre et l'envoie ; terminal B l'installe.
fn two_devices(dir: &Path, server: &MemoryServer) -> (LocalVault, LocalVault) {
    let mut a = LocalVault::create(dir.join("a.kdbx"), "Coffre", key(), fast_kdf()).unwrap();
    a.vault_mut().add_entry(&entry("Banque", "v1")).unwrap();
    a.save().unwrap();
    let report = a.sync(server, &options()).unwrap();
    assert!(report.uploaded);
    let b = LocalVault::clone_from_remote(dir.join("b.kdbx"), key(), OpenLimits::default(), server)
        .unwrap();
    (a, b)
}

#[test]
fn first_sync_creates_the_remote_vault() {
    let dir = tempfile::tempdir().unwrap();
    let server = MemoryServer::new();
    let mut a = LocalVault::create(dir.path().join("a.kdbx"), "Coffre", key(), fast_kdf()).unwrap();
    assert!(a.sync_state().local_dirty);
    let report = a.sync(&server, &options()).unwrap();
    assert!(report.uploaded && !report.downloaded);
    assert!(!a.sync_state().local_dirty);
    // Le serveur détient exactement le fichier local, lisible avec la clé.
    let remote = server.body().unwrap();
    assert_eq!(remote, std::fs::read(a.path()).unwrap());
    Vault::open(&remote, &key(), &OpenLimits::default()).unwrap();
}

#[test]
fn a_second_device_receives_changes() {
    let dir = tempfile::tempdir().unwrap();
    let server = MemoryServer::new();
    let (mut a, mut b) = two_devices(dir.path(), &server);
    assert_eq!(titles(&b), ["Banque"]);

    a.vault_mut().add_entry(&entry("Messagerie", "m")).unwrap();
    a.save().unwrap();
    a.sync(&server, &options()).unwrap();

    let report = b.sync(&server, &options()).unwrap();
    assert!(report.downloaded && !report.uploaded);
    assert_eq!(report.merge.created, 1);
    assert_eq!(titles(&b), ["Banque", "Messagerie"]);
    // Le résultat de la fusion est enregistré sur B.
    let reopened = LocalVault::open(b.path(), key(), OpenLimits::default()).unwrap();
    assert_eq!(titles(&reopened), ["Banque", "Messagerie"]);
}

#[test]
fn concurrent_edits_are_merged_without_loss() {
    let dir = tempfile::tempdir().unwrap();
    let server = MemoryServer::new();
    let (mut a, mut b) = two_devices(dir.path(), &server);
    let banque = a.vault().find("Banque")[0].id.clone();

    sleep(Duration::from_millis(1_100));
    a.vault_mut()
        .update_entry(&banque, &entry("Banque", "modifié sur A"))
        .unwrap();
    a.save().unwrap();
    b.vault_mut()
        .add_entry(&entry("Impots", "ajouté sur B"))
        .unwrap();
    b.save().unwrap();

    a.sync(&server, &options()).unwrap();
    let report = b.sync(&server, &options()).unwrap();
    assert!(report.downloaded && report.uploaded);
    a.sync(&server, &options()).unwrap();

    for device in [&a, &b] {
        assert_eq!(titles(device), ["Banque", "Impots"]);
        assert_eq!(
            device.vault().entry(&banque).unwrap().password.as_str(),
            "modifié sur A"
        );
    }
    let remote = Vault::open(&server.body().unwrap(), &key(), &OpenLimits::default()).unwrap();
    assert_eq!(remote.entries().len(), 2);
}

#[test]
fn a_write_between_download_and_upload_is_detected_and_merged() {
    let dir = tempfile::tempdir().unwrap();
    let server = MemoryServer::new();
    let (mut a, mut b) = two_devices(dir.path(), &server);

    // Version écrite par A, qui arrivera sur le serveur pendant la
    // synchronisation de B, entre son téléchargement et son envoi.
    a.vault_mut().add_entry(&entry("Messagerie", "A")).unwrap();
    a.save().unwrap();
    let from_a = std::fs::read(a.path()).unwrap();
    server.concurrent_write_before_next_store(from_a);

    b.vault_mut().add_entry(&entry("Impots", "B")).unwrap();
    b.save().unwrap();
    let report = b.sync(&server, &options()).unwrap();
    assert_eq!(report.conflicts, 1);
    assert!(report.uploaded);
    assert_eq!(server.rejected(), 1);

    let remote = Vault::open(&server.body().unwrap(), &key(), &OpenLimits::default()).unwrap();
    let mut names: Vec<String> = remote.entries().into_iter().map(|e| e.title).collect();
    names.sort();
    assert_eq!(names, ["Banque", "Impots", "Messagerie"]);
}

#[test]
fn own_upload_is_recognised_without_merging() {
    let dir = tempfile::tempdir().unwrap();
    let server = MemoryServer::new();
    let (mut a, _b) = two_devices(dir.path(), &server);
    let stores = server.stores();
    let report = a.sync(&server, &options()).unwrap();
    assert!(
        report.downloaded,
        "l'étiquette faible n'est pas conservée : relecture"
    );
    assert!(report.merge.is_empty());
    assert!(!report.uploaded);
    assert_eq!(server.stores(), stores);
    // Ensuite, l'étiquette forte suffit : plus de téléchargement.
    let report = a.sync(&server, &options()).unwrap();
    assert!(!report.downloaded && !report.uploaded);
}

#[test]
fn weak_etags_are_waited_out() {
    let dir = tempfile::tempdir().unwrap();
    let server = MemoryServer::new();
    let (mut a, mut b) = two_devices(dir.path(), &server);
    a.vault_mut().add_entry(&entry("Messagerie", "m")).unwrap();
    a.save().unwrap();
    a.sync(&server, &options()).unwrap();

    b.vault_mut().add_entry(&entry("Impots", "i")).unwrap();
    b.save().unwrap();
    server.weak_next_reads(2);
    let report = b.sync(&server, &options()).unwrap();
    assert_eq!(report.weak_waits, 2);
    assert!(report.uploaded);
    assert_eq!(
        server.rejected(),
        0,
        "aucun envoi avec une étiquette faible"
    );
}

#[test]
fn a_server_that_never_settles_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let server = MemoryServer::new();
    let (_a, mut b) = two_devices(dir.path(), &server);
    b.vault_mut().add_entry(&entry("Impots", "i")).unwrap();
    b.save().unwrap();
    server.weak_next_reads(100);
    assert!(matches!(
        b.sync(&server, &options()),
        Err(Error::Sync(SyncError::UnstableEtag))
    ));
}

#[test]
fn endless_conflicts_stop_after_the_attempt_limit() {
    let dir = tempfile::tempdir().unwrap();
    let server = MemoryServer::new();
    let (a, mut b) = two_devices(dir.path(), &server);
    server.concurrent_write_before_every_store(std::fs::read(a.path()).unwrap());
    b.vault_mut().add_entry(&entry("Impots", "i")).unwrap();
    b.save().unwrap();
    assert!(matches!(
        b.sync(&server, &options()),
        Err(Error::Sync(SyncError::TooManyConflicts))
    ));
    assert_eq!(server.rejected(), options().max_attempts);
    // Rien n'est perdu localement.
    assert!(b.sync_state().local_dirty);
    assert_eq!(titles(&b), ["Banque", "Impots"]);
}

#[test]
fn a_remote_vault_with_another_key_is_never_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let server = MemoryServer::new();
    let (_a, mut b) = two_devices(dir.path(), &server);
    // Un autre terminal a changé la phrase de passe du coffre.
    let mut changed = Vault::open(&server.body().unwrap(), &key(), &OpenLimits::default()).unwrap();
    let other_key = VaultKey::new().with_password("nouvelle phrase");
    server.put_raw(changed.to_bytes(&other_key).unwrap());
    let before = server.body();

    b.vault_mut().add_entry(&entry("Impots", "i")).unwrap();
    b.save().unwrap();
    assert!(matches!(
        b.sync(&server, &options()),
        Err(Error::Sync(SyncError::RemoteWrongKey))
    ));
    assert_eq!(server.body(), before);
}

#[test]
fn an_unrelated_or_corrupt_remote_vault_is_never_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let server = MemoryServer::new();
    let (_a, mut b) = two_devices(dir.path(), &server);
    b.vault_mut().add_entry(&entry("Impots", "i")).unwrap();
    b.save().unwrap();

    let mut unrelated = Vault::create("Autre coffre", fast_kdf()).unwrap();
    server.put_raw(unrelated.to_bytes(&key()).unwrap());
    let before = server.body();
    assert!(matches!(
        b.sync(&server, &options()),
        Err(Error::DifferentVaults)
    ));
    assert_eq!(server.body(), before);

    server.put_raw(b"contenu quelconque".to_vec());
    assert!(matches!(
        b.sync(&server, &options()),
        Err(Error::Sync(SyncError::RemoteUnreadable(_)))
    ));
    assert_eq!(server.body().as_deref(), Some(&b"contenu quelconque"[..]));
}

#[test]
fn deletions_reach_the_other_device() {
    let dir = tempfile::tempdir().unwrap();
    let server = MemoryServer::new();
    let (mut a, mut b) = two_devices(dir.path(), &server);
    let banque = a.vault().find("Banque")[0].id.clone();
    sleep(Duration::from_millis(1_100));
    a.vault_mut().delete_entry(&banque).unwrap();
    a.save().unwrap();
    a.sync(&server, &options()).unwrap();
    b.sync(&server, &options()).unwrap();
    assert!(titles(&b).is_empty());
}

#[test]
fn installing_a_device_requires_an_existing_remote_vault() {
    let dir = tempfile::tempdir().unwrap();
    let server = MemoryServer::new();
    assert!(matches!(
        LocalVault::clone_from_remote(
            dir.path().join("b.kdbx"),
            key(),
            OpenLimits::default(),
            &server
        ),
        Err(Error::Sync(SyncError::RemoteMissing))
    ));
}
