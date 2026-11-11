//! Essais de l'outil `lgs` : messages d'erreur, coffre vide, fichiers clés.
//!
//! Points relevés pendant la recette du jalon 0 (11 novembre 2026).
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::Path;
use std::process::{Command, Output};

/// Phrase de test, sans valeur secrète.
const PASSWORD: &str = "phrase de test, pas un secret";

fn lgs(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lgs"))
        .args(args)
        .current_dir(dir)
        .env("LGS_PASSWORD", PASSWORD)
        .env_remove("LGS_ENTRY_PASSWORD")
        .env_remove("LGS_WEBDAV_PASSWORD")
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Coffre rapide à ouvrir : 4 itérations suffisent pour ces essais.
fn new_vault(dir: &Path, extra: &[&str]) {
    let mut args = vec!["new", "coffre.kdbx", "--iterations", "4"];
    args.extend_from_slice(extra);
    let out = lgs(dir, &args);
    assert!(out.status.success(), "{}", text(&out.stderr));
}

#[test]
fn a_missing_vault_is_named() {
    let dir = tempfile::tempdir().unwrap();
    let out = lgs(dir.path(), &["list", "absent.kdbx"]);
    assert!(!out.status.success());
    let err = text(&out.stderr);
    assert!(
        err.contains("coffre introuvable") && err.contains("absent.kdbx"),
        "{err}"
    );
}

#[test]
fn a_missing_key_file_is_named() {
    let dir = tempfile::tempdir().unwrap();
    new_vault(dir.path(), &[]);
    let out = lgs(dir.path(), &["list", "coffre.kdbx", "-k", "absente.keyx"]);
    assert!(!out.status.success());
    let err = text(&out.stderr);
    assert!(
        err.contains("fichier clé introuvable") && err.contains("absente.keyx"),
        "{err}"
    );
}

#[test]
fn a_missing_version_to_merge_is_named() {
    let dir = tempfile::tempdir().unwrap();
    new_vault(dir.path(), &[]);
    let out = lgs(dir.path(), &["merge", "coffre.kdbx", "copie-absente.kdbx"]);
    assert!(!out.status.success());
    let err = text(&out.stderr);
    assert!(
        err.contains("coffre introuvable") && err.contains("copie-absente.kdbx"),
        "{err}"
    );
}

#[test]
fn an_empty_vault_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    new_vault(dir.path(), &[]);
    let out = lgs(dir.path(), &["list", "coffre.kdbx"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(out.stdout.is_empty());
    assert!(text(&out.stderr).contains("aucune entrée"));
}

#[test]
fn lgs_creates_a_keepass_xml_key_file_and_never_overwrites_it() {
    let dir = tempfile::tempdir().unwrap();
    let out = lgs(dir.path(), &["keyfile", "cle.keyx"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let content = std::fs::read_to_string(dir.path().join("cle.keyx")).unwrap();
    assert!(content.contains("<Version>2.0</Version>"), "{content}");

    let again = lgs(dir.path(), &["keyfile", "cle.keyx"]);
    assert!(!again.status.success());
    assert!(text(&again.stderr).contains("existe déjà"));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("cle.keyx")).unwrap(),
        content
    );

    // Le fichier clé sert aussitôt.
    new_vault(dir.path(), &["-k", "cle.keyx"]);
    let add = lgs(
        dir.path(),
        &[
            "add",
            "coffre.kdbx",
            "-k",
            "cle.keyx",
            "--title",
            "Banque",
            "--generate",
            "20",
        ],
    );
    assert!(add.status.success(), "{}", text(&add.stderr));
    let list = lgs(dir.path(), &["list", "coffre.kdbx", "-k", "cle.keyx"]);
    assert!(text(&list.stdout).contains("Banque"));
    // Sans le fichier clé, le coffre ne s'ouvre pas.
    let without = lgs(dir.path(), &["list", "coffre.kdbx"]);
    assert!(!without.status.success());
}

#[test]
fn a_damaged_key_file_is_reported_as_such() {
    let dir = tempfile::tempdir().unwrap();
    assert!(lgs(dir.path(), &["keyfile", "cle.keyx"]).status.success());
    new_vault(dir.path(), &["-k", "cle.keyx"]);
    let path = dir.path().join("cle.keyx");
    let content = std::fs::read_to_string(&path).unwrap();
    let data_line = content.lines().nth(7).unwrap().to_owned();
    let first = data_line.trim_start().chars().next().unwrap();
    let replacement = if first == 'A' { "B" } else { "A" };
    let damaged = content.replacen(&data_line, &data_line.replacen(first, replacement, 1), 1);
    std::fs::write(&path, damaged).unwrap();
    let out = lgs(dir.path(), &["list", "coffre.kdbx", "-k", "cle.keyx"]);
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("fichier clé endommagé"));
}
