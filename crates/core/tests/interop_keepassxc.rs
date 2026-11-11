//! Interopérabilité avec KeePassXC, implémentation indépendante du format.
//!
//! Ignoré si `keepassxc-cli` est absent, sauf avec `LGS_REQUIRE_KEEPASSXC=1`.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::*;
use ligrivsstore_core::header::{self, Argon2Variant, Kdf};
use ligrivsstore_core::{LocalVault, OpenLimits, Vault, VaultKey};

/// Lance keepassxc-cli ; `input` est envoyé sur l'entrée standard (phrase de
/// passe, puis éventuelles réponses).
fn xc(cli: &Path, args: &[&str], input: &str) -> (bool, String) {
    let mut child = Command::new(cli)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), text)
}

fn keyfile(dir: &Path) -> (PathBuf, Vec<u8>) {
    let mut bytes = vec![0u8; 64];
    getrandom::fill(&mut bytes).unwrap();
    let path = dir.join("cle.keyx");
    std::fs::write(&path, &bytes).unwrap();
    (path, bytes)
}

#[test]
fn a_vault_written_by_the_core_is_read_by_keepassxc() {
    let Some(cli) = keepassxc_cli() else { return };
    let dir = tempfile::tempdir().unwrap();
    let (keyfile_path, keyfile_bytes) = keyfile(dir.path());
    let path = dir.path().join("coffre.kdbx");
    let full_key = key().with_keyfile(&keyfile_bytes).unwrap();
    let mut local = LocalVault::create(&path, "Coffre", full_key, fast_kdf()).unwrap();
    local
        .vault_mut()
        .add_entry(&entry("Banque", "Mot-de-passe-protégé-éà"))
        .unwrap();
    local.save().unwrap();

    let file = path.to_str().unwrap();
    let k = keyfile_path.to_str().unwrap();
    let input = format!("{PASSWORD}\n");
    let (ok, listing) = xc(&cli, &["ls", "-q", "-k", k, file], &input);
    assert!(ok && listing.contains("Banque"), "{listing}");
    let (ok, shown) = xc(
        &cli,
        &[
            "show", "-q", "-s", "-a", "Password", "-k", k, file, "Banque",
        ],
        &input,
    );
    assert!(ok && shown.contains("Mot-de-passe-protégé-éà"), "{shown}");
    let (ok, info) = xc(&cli, &["db-info", "-q", "-k", k, file], &input);
    assert!(ok, "{info}");
    assert!(info.contains("Argon2id"), "{info}");
    assert!(info.contains("AES 256"), "{info}");
    // Sans le fichier clé, KeePassXC refuse le coffre.
    let (ok, _) = xc(&cli, &["ls", "-q", file], &input);
    assert!(!ok);
}

#[test]
fn a_keepassxc_vault_is_updated_by_the_core_and_read_back() {
    let Some(cli) = keepassxc_cli() else { return };
    let dir = tempfile::tempdir().unwrap();
    let (keyfile_path, keyfile_bytes) = keyfile(dir.path());
    let path = dir.path().join("keepassxc.kdbx");
    let file = path.to_str().unwrap();
    let k = keyfile_path.to_str().unwrap();

    // KeePassXC crée le coffre (KDBX 3.1 et AES-KDF avec keepassxc-cli 2.7)
    // et y ajoute une entrée.
    let (ok, out) = xc(
        &cli,
        &[
            "db-create",
            "-q",
            "--set-key-file",
            k,
            "-p",
            "-t",
            "100",
            file,
        ],
        &format!("{PASSWORD}\n{PASSWORD}\n"),
    );
    assert!(ok, "{out}");
    let (ok, out) = xc(
        &cli,
        &[
            "add",
            "-q",
            "-k",
            k,
            "-u",
            "hermann",
            "--url",
            "https://mail.exemple.test",
            "-p",
            file,
            "Messagerie",
        ],
        &format!("{PASSWORD}\nmot-de-passe-keepassxc\n"),
    );
    assert!(ok, "{out}");
    let created_by_keepassxc = header::inspect(&std::fs::read(&path).unwrap()).unwrap();
    eprintln!(
        "coffre créé par keepassxc-cli : KDBX {}.{}, {}",
        created_by_keepassxc.major, created_by_keepassxc.minor, created_by_keepassxc.kdf
    );

    // Le noyau l'ouvre, modifie l'entrée, en ajoute une et l'enregistre.
    let full_key = VaultKey::new()
        .with_password(PASSWORD)
        .with_keyfile(&keyfile_bytes)
        .unwrap();
    let mut local = LocalVault::open(&path, full_key, OpenLimits::default()).unwrap();
    let id = local.vault().find("Messagerie")[0].id.clone();
    let mut changed = entry("Messagerie", "modifié-par-le-noyau");
    changed.username = "hermann".into();
    changed.url = "https://mail.exemple.test".into();
    local.vault_mut().update_entry(&id, &changed).unwrap();
    local
        .vault_mut()
        .add_entry(&entry("Banque", "ajouté-par-le-noyau"))
        .unwrap();
    local.save().unwrap();

    // Le fichier est désormais en KDBX 4.1, avec Argon2id.
    let info = header::inspect(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!((info.major, info.minor), (4, 1));
    assert!(matches!(
        info.kdf,
        Kdf::Argon2 {
            variant: Argon2Variant::Argon2id,
            ..
        }
    ));

    // KeePassXC relit tout.
    let input = format!("{PASSWORD}\n");
    let (ok, shown) = xc(
        &cli,
        &[
            "show",
            "-q",
            "-s",
            "-a",
            "Password",
            "-k",
            k,
            file,
            "Messagerie",
        ],
        &input,
    );
    assert!(ok && shown.contains("modifié-par-le-noyau"), "{shown}");
    let (ok, shown) = xc(
        &cli,
        &[
            "show", "-q", "-s", "-a", "Password", "-k", k, file, "Banque",
        ],
        &input,
    );
    assert!(ok && shown.contains("ajouté-par-le-noyau"), "{shown}");
}

#[test]
fn edits_made_with_keepassxc_are_merged_by_the_core() {
    let Some(cli) = keepassxc_cli() else { return };
    let dir = tempfile::tempdir().unwrap();
    let a_path = dir.path().join("a.kdbx");
    let b_path = dir.path().join("b.kdbx");

    // Copie commune, puis A (noyau) et B (KeePassXC) divergent.
    let mut a = LocalVault::create(&a_path, "Coffre", key(), fast_kdf()).unwrap();
    let banque = a.vault_mut().add_entry(&entry("Banque", "v1")).unwrap();
    a.save().unwrap();
    std::fs::copy(&a_path, &b_path).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1_100));

    a.vault_mut()
        .update_entry(&banque, &entry("Banque", "modifié-sur-A"))
        .unwrap();
    a.save().unwrap();
    let (ok, out) = xc(
        &cli,
        &[
            "add",
            "-q",
            "-u",
            "hermann",
            "-p",
            b_path.to_str().unwrap(),
            "Impots",
        ],
        &format!("{PASSWORD}\najouté-sur-B\n"),
    );
    assert!(ok, "{out}");

    let b = Vault::open(
        &std::fs::read(&b_path).unwrap(),
        &key(),
        &OpenLimits::default(),
    )
    .unwrap();
    let report = a.vault_mut().merge_from(&b).unwrap();
    assert!(report.created >= 1, "{report:?}");
    a.save().unwrap();

    let input = format!("{PASSWORD}\n");
    let file = a_path.to_str().unwrap();
    let (ok, shown) = xc(
        &cli,
        &["show", "-q", "-s", "-a", "Password", file, "Banque"],
        &input,
    );
    assert!(ok && shown.contains("modifié-sur-A"), "{shown}");
    let (ok, shown) = xc(
        &cli,
        &["show", "-q", "-s", "-a", "Password", file, "Impots"],
        &input,
    );
    assert!(ok && shown.contains("ajouté-sur-B"), "{shown}");
}

#[test]
fn a_key_file_generated_by_the_core_is_accepted_by_keepassxc() {
    let Some(cli) = keepassxc_cli() else { return };
    let dir = tempfile::tempdir().unwrap();
    let keyfile_path = dir.path().join("cle.keyx");
    ligrivsstore_core::keyfile::create(&keyfile_path).unwrap();
    let keyfile_bytes = std::fs::read(&keyfile_path).unwrap();
    let path = dir.path().join("coffre.kdbx");
    let full_key = key().with_keyfile(&keyfile_bytes).unwrap();
    let mut local = LocalVault::create(&path, "Coffre", full_key, fast_kdf()).unwrap();
    local
        .vault_mut()
        .add_entry(&entry("Banque", "secret-de-test"))
        .unwrap();
    local.save().unwrap();

    // KeePassXC vérifie la somme de contrôle du fichier clé avant de l'utiliser.
    let file = path.to_str().unwrap();
    let k = keyfile_path.to_str().unwrap();
    let (ok, listing) = xc(&cli, &["ls", "-q", "-k", k, file], &format!("{PASSWORD}\n"));
    assert!(ok && listing.contains("Banque"), "{listing}");
}

#[test]
fn a_key_file_generated_by_keepassxc_is_read_by_the_core() {
    let Some(cli) = keepassxc_cli() else { return };
    let dir = tempfile::tempdir().unwrap();
    let keyfile_path = dir.path().join("keepassxc.keyx");
    let path = dir.path().join("keepassxc.kdbx");

    // keepassxc-cli crée le fichier clé (XML 2.0) puisqu'il n'existe pas.
    let (ok, out) = xc(
        &cli,
        &[
            "db-create",
            "-q",
            "--set-key-file",
            keyfile_path.to_str().unwrap(),
            "-p",
            "-t",
            "100",
            path.to_str().unwrap(),
        ],
        &format!("{PASSWORD}\n{PASSWORD}\n"),
    );
    assert!(ok, "{out}");
    let keyfile_bytes = std::fs::read(&keyfile_path).unwrap();
    let text = String::from_utf8_lossy(&keyfile_bytes);
    assert!(text.contains("<Version>2.0</Version>"), "{text}");
    ligrivsstore_core::keyfile::verify_checksum(&keyfile_bytes).unwrap();

    let full_key = VaultKey::new()
        .with_password(PASSWORD)
        .with_keyfile(&keyfile_bytes)
        .unwrap();
    LocalVault::open(&path, full_key, OpenLimits::default()).unwrap();
}
