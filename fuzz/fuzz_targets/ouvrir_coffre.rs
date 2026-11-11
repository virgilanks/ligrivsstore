//! Cible : bibliothèque KDBX appelée **sans** le garde-fou du noyau, sur les
//! seules entrées que le contrôle d'en-tête du noyau laisse passer.
//!
//! Un arrêt brutal trouvé ici est un cas que seul le garde-fou (rattrapage de la
//! panique) protège : à signaler à l'auteur de la bibliothèque et à couvrir par
//! le contrôle d'en-tête.
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use ligrivsstore_core::{OpenLimits, header};

/// Plafonds réduits pour garder plusieurs centaines d'essais par seconde.
static LIMITS: LazyLock<OpenLimits> = LazyLock::new(|| OpenLimits {
    max_argon2_memory_bytes: 2 * 1024 * 1024,
    max_argon2_iterations: 2,
    max_argon2_parallelism: 2,
    max_aes_rounds: 20_000,
    ..OpenLimits::default()
});

/// Phrase de passe des graines (fuzz/seeds) : les mutations peuvent ainsi
/// atteindre le déchiffrement.
const PASSWORD: &str = "phrase de test non secrète";

fuzz_target!(|data: &[u8]| {
    let Ok(info) = header::inspect(data) else {
        return;
    };
    if LIMITS.check(&info).is_err() {
        return;
    }
    let _ = keepass::Database::parse(data, keepass::DatabaseKey::new().with_password(PASSWORD));
});
