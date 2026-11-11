//! Mesure : comportement de la bibliothèque KDBX seule, puis du noyau, sur des
//! milliers de fichiers altérés. Le noyau doit toujours renvoyer une erreur,
//! même quand la bibliothèque s'arrête brutalement.
//!
//! Fichier de test séparé : il remplace le gestionnaire de panique global
//! pour ne pas inonder la sortie.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::panic::{AssertUnwindSafe, catch_unwind};

use common::*;
use ligrivsstore_core::{OpenLimits, Vault};

/// Générateur pseudo-aléatoire déterministe (xorshift), pour un essai
/// reproductible.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn library_crashes_are_contained_by_the_core() {
    const SAMPLES: usize = 3_000;
    let base = tiny_vault_bytes(PASSWORD);
    let mut rng = XorShift(0x1234_5678_9ABC_DEF0);
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let mut library_panics = 0;
    let mut prevented_by_header = 0;
    let mut caught_after_header = 0;
    let mut library_errors = 0;
    let mut core_errors = 0;
    let mut core_opened_altered = 0;
    for _ in 0..SAMPLES {
        let mut data = base.clone();
        let header_only = rng.below(4) != 0;
        for _ in 0..=rng.below(4) {
            let span = if header_only {
                data.len().min(260)
            } else {
                data.len()
            };
            let i = rng.below(span);
            data[i] ^= (rng.below(255) + 1) as u8;
        }
        if rng.below(10) == 0 {
            let cut = rng.below(data.len());
            data.truncate(cut);
        }
        if data == base {
            continue;
        }
        let library = catch_unwind(AssertUnwindSafe(|| {
            keepass::Database::parse(&data, keepass::DatabaseKey::new().with_password(PASSWORD))
        }));
        match library {
            Err(_) => {
                library_panics += 1;
                // L'arrêt brutal est-il évité dès le contrôle d'en-tête, ou
                // seulement rattrapé ensuite ?
                let header_rejects = ligrivsstore_core::header::inspect(&data)
                    .and_then(|info| OpenLimits::default().check(&info))
                    .is_err();
                if header_rejects {
                    prevented_by_header += 1;
                } else {
                    caught_after_header += 1;
                }
            }
            Ok(Err(_)) => library_errors += 1,
            Ok(Ok(_)) => {}
        }
        match catch_unwind(AssertUnwindSafe(|| {
            Vault::open(&data, &key(), &OpenLimits::default())
        })) {
            Ok(Err(_)) => core_errors += 1,
            Ok(Ok(_)) => core_opened_altered += 1,
            Err(_) => {
                std::panic::set_hook(previous_hook);
                panic!("le noyau a laissé passer un arrêt brutal");
            }
        }
    }
    std::panic::set_hook(previous_hook);
    eprintln!(
        "fichiers altérés : bibliothèque seule = {library_panics} arrêts brutaux \
         ({prevented_by_header} évités par le contrôle d'en-tête, {caught_after_header} rattrapés ensuite), \
         {library_errors} erreurs ; noyau = {core_errors} erreurs, {core_opened_altered} ouvertures"
    );
    assert_eq!(core_opened_altered, 0);
    assert!(core_errors > 0);
}
