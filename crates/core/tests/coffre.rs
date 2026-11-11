//! Coffre : création, ouverture, enregistrement, politique de dérivation,
//! en-têtes hostiles.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::time::{Duration, Instant};

use common::*;
use ligrivsstore_core::header::{self, Argon2Variant, Kdf};
use ligrivsstore_core::{Error, LocalVault, OpenLimits, Vault, VaultKey};
use zeroize::Zeroizing;

#[test]
fn round_trip_keeps_every_field() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("coffre.kdbx");
    let mut local = LocalVault::create(&path, "Coffre d'Hermann", key(), fast_kdf()).unwrap();
    let banque = local
        .vault_mut()
        .add_entry(&entry("Banque", "Tr0p-s3cret!"))
        .unwrap();
    let mail = local
        .vault_mut()
        .add_entry(&entry("Messagerie", "autre secret"))
        .unwrap();
    local.save().unwrap();

    let reopened = LocalVault::open(&path, key(), OpenLimits::default()).unwrap();
    let vault = reopened.vault();
    assert_eq!(vault.name(), Some("Coffre d'Hermann"));
    assert_eq!(vault.format_version(), "KDBX4.1");
    assert_eq!(vault.entries().len(), 2);
    let details = vault.entry(&banque).unwrap();
    let expected = entry("Banque", "Tr0p-s3cret!");
    assert_eq!(details.title, expected.title);
    assert_eq!(details.url, expected.url);
    assert_eq!(details.username, expected.username);
    assert_eq!(details.password.as_str(), "Tr0p-s3cret!");
    assert_eq!(details.notes, expected.notes);
    assert_eq!(
        vault.entry(&mail).unwrap().password.as_str(),
        "autre secret"
    );
    assert_eq!(vault.find("messag").len(), 1);
    assert_eq!(vault.find("EXEMPLE").len(), 2);
}

#[test]
fn written_file_uses_our_derivation_policy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("coffre.kdbx");
    LocalVault::create(&path, "Essai", key(), fast_kdf()).unwrap();
    let info = header::inspect(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!((info.major, info.minor), (4, 1));
    assert_eq!(
        info.kdf,
        Kdf::Argon2 {
            variant: Argon2Variant::Argon2id,
            memory_bytes: 32 * 1024 * 1024,
            iterations: fast_kdf().iterations,
            parallelism: 2,
            version: 0x13,
        }
    );
}

#[test]
fn weak_library_defaults_are_never_written() {
    // Coffre écrit par la bibliothèque avec 1 Mio et 1 passe : à la première
    // écriture par le noyau, la dérivation passe à 32 Mio et 4 passes au moins.
    let bytes = tiny_vault_bytes(PASSWORD);
    let mut vault = Vault::open(&bytes, &key(), &OpenLimits::default()).unwrap();
    let rewritten = vault.to_bytes(&key()).unwrap();
    match header::inspect(&rewritten).unwrap().kdf {
        Kdf::Argon2 {
            variant,
            memory_bytes,
            iterations,
            ..
        } => {
            assert_eq!(variant, Argon2Variant::Argon2id);
            assert_eq!(memory_bytes, 32 * 1024 * 1024);
            assert!(iterations >= 4);
        }
        other => panic!("dérivation inattendue : {other:?}"),
    }
}

#[test]
fn wrong_password_or_missing_keyfile_is_reported_as_wrong_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("coffre.kdbx");
    let keyfile = b"contenu aleatoire du fichier cle pour le test".to_vec();
    let full = key().with_keyfile(&keyfile).unwrap();
    LocalVault::create(&path, "Essai", full.clone(), fast_kdf()).unwrap();

    let bytes = std::fs::read(&path).unwrap();
    let limits = OpenLimits::default();
    assert!(Vault::open(&bytes, &full, &limits).is_ok());
    assert!(matches!(
        Vault::open(&bytes, &key(), &limits),
        Err(Error::WrongKey)
    ));
    let wrong = VaultKey::new()
        .with_password("autre phrase")
        .with_keyfile(&keyfile)
        .unwrap();
    assert!(matches!(
        Vault::open(&bytes, &wrong, &limits),
        Err(Error::WrongKey)
    ));
    assert!(matches!(
        Vault::open(&bytes, &VaultKey::new(), &limits),
        Err(Error::InvalidInput(_))
    ));
}

#[test]
fn hostile_derivation_parameters_are_refused_without_computation() {
    let bytes = tiny_vault_bytes(PASSWORD);
    let cases = [
        (b'M', 1u64 << 41, "2 Tio de mémoire"),
        (b'I', 1u64 << 40, "10^12 itérations"),
    ];
    for (name, value, label) in cases {
        let hostile = rewrite_kdf_dictionary(&bytes, |d| set_u64_parameter(d, name, value));
        let start = Instant::now();
        let outcome = Vault::open(&hostile, &key(), &OpenLimits::default());
        assert!(
            matches!(outcome, Err(Error::KdfRejected(_))),
            "{label} : {outcome:?}"
        );
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "{label} : refus trop lent"
        );
    }
}

#[test]
fn malformed_parameter_dictionary_is_an_error_not_a_crash() {
    // Paramètre numérique de longueur nulle : la bibliothèque le lit sans
    // contrôle de longueur.
    let bytes = tiny_vault_bytes(PASSWORD);
    let hostile = rewrite_kdf_dictionary(&bytes, |d| {
        let end = d.len() - 1;
        d.splice(end..end, [0x04, 1, 0, 0, 0, b'X', 0, 0, 0, 0]);
    });
    assert!(matches!(
        Vault::open(&hostile, &key(), &OpenLimits::default()),
        Err(Error::Corrupt(_))
    ));
    // Constat sur la bibliothèque elle-même (consigné dans la documentation).
    let library = std::panic::catch_unwind(|| {
        keepass::Database::parse(
            &hostile,
            keepass::DatabaseKey::new().with_password(PASSWORD),
        )
        .is_ok()
    });
    eprintln!(
        "bibliothèque keepass sur ce fichier : {}",
        if library.is_err() {
            "arrêt brutal (panic)"
        } else {
            "erreur ordinaire"
        }
    );
}

#[test]
fn oversized_file_is_refused() {
    let bytes = tiny_vault_bytes(PASSWORD);
    let limits = OpenLimits {
        max_file_bytes: bytes.len() as u64 - 1,
        ..OpenLimits::default()
    };
    assert!(matches!(
        Vault::open(&bytes, &key(), &limits),
        Err(Error::TooLarge { .. })
    ));
}

#[test]
fn creating_over_an_existing_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("coffre.kdbx");
    LocalVault::create(&path, "Essai", key(), fast_kdf()).unwrap();
    assert!(matches!(
        LocalVault::create(&path, "Essai", key(), fast_kdf()),
        Err(Error::AlreadyExists(_))
    ));
}

#[test]
fn each_save_keeps_a_local_backup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("coffre.kdbx");
    let mut local = LocalVault::create(&path, "Essai", key(), fast_kdf()).unwrap();
    for i in 0..3 {
        local
            .vault_mut()
            .add_entry(&entry(&format!("Site {i}"), "x"))
            .unwrap();
        local.save().unwrap();
    }
    let backups = local.backups().unwrap();
    assert_eq!(backups.len(), 3);
    // Chaque sauvegarde est un coffre complet, lisible avec la clé.
    for backup in backups {
        let bytes = std::fs::read(&backup.path).unwrap();
        Vault::open(&bytes, &key(), &OpenLimits::default()).unwrap();
    }
}

#[test]
fn deleted_entries_disappear() {
    let mut vault = Vault::create("Essai", fast_kdf()).unwrap();
    let id = vault.add_entry(&entry("Banque", "x")).unwrap();
    vault.delete_entry(&id).unwrap();
    assert!(vault.entries().is_empty());
    assert!(matches!(vault.entry(&id), Err(Error::EntryNotFound(_))));
    assert!(matches!(
        vault.delete_entry(&id),
        Err(Error::EntryNotFound(_))
    ));
}

#[test]
fn passwords_are_returned_in_zeroizing_buffers() {
    let mut vault = Vault::create("Essai", fast_kdf()).unwrap();
    let id = vault.add_entry(&entry("Banque", "secret")).unwrap();
    let password: Zeroizing<String> = vault.entry(&id).unwrap().password;
    assert_eq!(password.as_str(), "secret");
}

#[test]
fn reserved_entries_carry_their_role_across_saves_and_merges() {
    use ligrivsstore_core::{ROLE_FIELD, SYNC_ROLE};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("coffre.kdbx");
    let mut local = LocalVault::create(&path, "Essai", key(), fast_kdf()).unwrap();
    let ordinary = local
        .vault_mut()
        .add_entry(&entry("Banque", "secret"))
        .unwrap();
    assert_eq!(local.vault().role_entry(SYNC_ROLE), None);
    let reserved = local
        .vault_mut()
        .add_role_entry(&entry("Serveur", "mot de passe WebDAV"), SYNC_ROLE)
        .unwrap();
    local.save().unwrap();

    let reopened = LocalVault::open(&path, key(), OpenLimits::default()).unwrap();
    let vault = reopened.vault();
    assert_eq!(vault.role_entry(SYNC_ROLE), Some(reserved.clone()));
    let roles: Vec<_> = vault
        .entries()
        .into_iter()
        .map(|e| (e.id, e.role))
        .collect();
    assert!(roles.contains(&(ordinary, None)));
    assert!(roles.contains(&(reserved.clone(), Some(SYNC_ROLE.to_owned()))));
    // Le rôle est un attribut ordinaire pour les autres applications KeePass.
    let raw = vault
        .database()
        .iter_all_entries()
        .find(|e| e.id().uuid().to_string() == reserved)
        .unwrap();
    assert_eq!(raw.get(ROLE_FIELD), Some(SYNC_ROLE));

    // Modifier l'entrée réservée garde son rôle ; la fusion le transmet.
    let mut other = vault.clone();
    other
        .update_entry(&reserved, &entry("Serveur", "nouveau mot de passe"))
        .unwrap();
    let mut merged = vault.clone();
    merged.merge_from(&other).unwrap();
    assert_eq!(merged.role_entry(SYNC_ROLE), Some(reserved.clone()));
    assert_eq!(
        merged.entry(&reserved).unwrap().password.as_str(),
        "nouveau mot de passe"
    );
    assert!(merged.add_role_entry(&entry("X", "y"), " ").is_err());
}

#[test]
fn restoring_a_backup_brings_entries_back_without_losing_anything() {
    use ligrivsstore_core::SYNC_ROLE;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("coffre.kdbx");
    let mut local = LocalVault::create(&path, "Essai", key(), fast_kdf()).unwrap();
    let banque = local.vault_mut().add_entry(&entry("Banque", "v1")).unwrap();
    let mail = local
        .vault_mut()
        .add_entry(&entry("Messagerie", "m1"))
        .unwrap();
    let serveur = local
        .vault_mut()
        .add_role_entry(&entry("Serveur", "w1"), SYNC_ROLE)
        .unwrap();
    local.save().unwrap();

    // Après la sauvegarde : une modification, une suppression, un ajout, et un
    // nouveau mot de passe du serveur.
    local
        .vault_mut()
        .update_entry(&banque, &entry("Banque", "v2"))
        .unwrap();
    local.vault_mut().delete_entry(&mail).unwrap();
    let journal = local
        .vault_mut()
        .add_entry(&entry("Journal", "j1"))
        .unwrap();
    local
        .vault_mut()
        .update_entry(&serveur, &entry("Serveur", "w2"))
        .unwrap();
    local.save().unwrap();

    let backups = local.backups().unwrap();
    // La sauvegarde la plus récente est l'état d'avant ces changements.
    let newest = backups.first().unwrap();
    assert!(newest.replaced_utc.as_deref().unwrap().ends_with('Z'));
    let name = newest
        .path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let report = local.restore_backup(&name).unwrap();
    assert_eq!(report.restored, 1, "{report:?}");
    assert_eq!(report.recreated, 1, "{report:?}");
    assert_eq!(report.skipped, 0);

    let vault = LocalVault::open(&path, key(), OpenLimits::default()).unwrap();
    let vault = vault.vault();
    let banque_now = vault.entry(&banque).unwrap();
    assert_eq!(banque_now.password.as_str(), "v1");
    assert!(
        banque_now.history_len >= 2,
        "la version v2 reste dans l'historique"
    );
    let titles: Vec<_> = vault.entries().into_iter().map(|e| e.title).collect();
    assert!(titles.contains(&"Messagerie".to_owned()), "{titles:?}");
    assert!(vault.entry(&journal).is_ok(), "l'ajout postérieur reste");
    assert_eq!(
        vault.entry(&serveur).unwrap().password.as_str(),
        "w2",
        "l'entrée réservée n'est pas rétablie"
    );

    // Les noms inconnus et les fichiers hors du dossier des sauvegardes sont
    // refusés.
    assert!(local.open_backup("inconnu.kdbx").is_err());
    assert!(local.open_backup("../coffre.kdbx").is_err());
}

#[test]
fn a_backup_of_another_vault_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("coffre.kdbx");
    let mut local = LocalVault::create(&path, "Essai", key(), fast_kdf()).unwrap();
    local.vault_mut().add_entry(&entry("A", "a")).unwrap();
    local.save().unwrap();
    // Un autre coffre, même clé, déposé dans le dossier des sauvegardes.
    let stranger = Vault::create("Étranger", fast_kdf())
        .unwrap()
        .to_bytes(&key())
        .unwrap();
    let backups_dir = dir.path().join("coffre.kdbx.sauvegardes");
    std::fs::create_dir_all(&backups_dir).unwrap();
    let intrus = "coffre.29991231T235959.000000Z.000.kdbx";
    std::fs::write(backups_dir.join(intrus), stranger).unwrap();
    assert!(matches!(
        local.open_backup(intrus),
        Err(Error::DifferentVaults)
    ));
}
