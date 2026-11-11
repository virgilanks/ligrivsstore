//! Tests aléatoires du lecteur : aucun fichier, même hostile, ne doit arrêter
//! l'application ni s'ouvrir s'il a été altéré.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::sync::LazyLock;

use common::*;
use ligrivsstore_core::{OpenLimits, Vault, header};
use proptest::prelude::*;

/// Coffre valide à dérivation minimale (une tentative d'ouverture coûte peu).
static BASE: LazyLock<Vec<u8>> = LazyLock::new(|| tiny_vault_bytes(PASSWORD));

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 512,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn arbitrary_bytes_are_rejected(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = header::inspect(&data);
        prop_assert!(Vault::open(&data, &key(), &OpenLimits::default()).is_err());
    }

    #[test]
    fn altered_vaults_never_open(
        flips in proptest::collection::vec((any::<prop::sample::Index>(), 1u8..=255), 1..6),
        header_bias in any::<bool>(),
        truncate in proptest::option::of(any::<prop::sample::Index>()),
    ) {
        let mut data = BASE.clone();
        for (index, mask) in flips {
            // La moitié des cas vise l'en-tête, seule partie lue avant tout
            // contrôle d'intégrité.
            let span = if header_bias { data.len().min(300) } else { data.len() };
            let i = index.index(span);
            data[i] ^= mask;
        }
        if let Some(cut) = truncate {
            data.truncate(cut.index(data.len()));
        }
        let outcome = Vault::open(&data, &key(), &OpenLimits::default());
        prop_assert!(outcome.is_err() || data == *BASE);
    }

    #[test]
    fn prefixed_bytes_never_open(extra in proptest::collection::vec(any::<u8>(), 1..64)) {
        let mut data = extra;
        data.extend_from_slice(&BASE);
        prop_assert!(Vault::open(&data, &key(), &OpenLimits::default()).is_err());
    }

    /// Constat : la bibliothèque ignore les octets ajoutés après le dernier bloc
    /// (le contenu, protégé par HMAC, reste authentique). Le coffre ouvert doit
    /// alors être strictement identique à l'original.
    #[test]
    fn appended_bytes_never_alter_content(extra in proptest::collection::vec(any::<u8>(), 1..64)) {
        let mut data = BASE.clone();
        data.extend_from_slice(&extra);
        if let Ok(vault) = Vault::open(&data, &key(), &OpenLimits::default()) {
            let original = Vault::open(&BASE, &key(), &OpenLimits::default()).unwrap();
            prop_assert_eq!(vault.entries(), original.entries());
            let id = &original.entries()[0].id;
            let opened = vault.entry(id).unwrap();
            let expected = original.entry(id).unwrap();
            prop_assert_eq!(opened.password.as_str(), expected.password.as_str());
        }
    }
}

#[test]
fn the_unaltered_base_opens() {
    Vault::open(&BASE, &key(), &OpenLimits::default()).unwrap();
}

/// Génère les graines du fuzzing (fichiers de `fuzz/seeds`) :
/// `LGS_FUZZ_SEEDS=fuzz/seeds cargo test -p ligrivsstore-core --test robustesse -- --ignored`
#[test]
#[ignore = "génère les graines du fuzzing à la demande"]
fn write_fuzz_seeds() {
    let Ok(dir) = std::env::var("LGS_FUZZ_SEEDS") else {
        return;
    };
    let dir = std::path::Path::new(&dir);
    for target in ["ouvrir_coffre", "lire_entete"] {
        let path = dir.join(target);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("kdbx41-argon2id-1mio"), &*BASE).unwrap();
    }
}
