//! Politique de dérivation de clé (Argon2id).
//!
//! Choix (voir `docs/decisions/0004-derivation-argon2id.md`) :
//! - Argon2id, version 1.3, 2 voies ;
//! - 32 Mio de mémoire à la création, entre 32 et 64 Mio à l'enregistrement :
//!   l'extension AutoFill d'iOS ne dispose que d'environ 120 Mo ;
//! - nombre d'itérations calibré pour environ une seconde sur le terminal le plus
//!   lent, jamais moins de [`MIN_ITERATIONS`].
//!
//! La bibliothèque KDBX propose par défaut Argon2d avec 1 Mio de mémoire : ces
//! valeurs ne sont jamais utilisées.

use std::time::{Duration, Instant};

use keepass::config::KdfConfig;

use crate::error::{Error, Result};
use crate::header::{Argon2Variant, Kdf};

/// Mémoire minimale écrite par le noyau : 32 Mio.
pub const MIN_MEMORY_BYTES: u64 = 32 * 1024 * 1024;
/// Mémoire maximale écrite par le noyau : 64 Mio (limite de l'AutoFill d'iOS).
pub const MAX_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
/// Mémoire à la création d'un coffre : 32 Mio.
pub const DEFAULT_MEMORY_BYTES: u64 = MIN_MEMORY_BYTES;
/// Nombre de voies à la création d'un coffre.
pub const DEFAULT_PARALLELISM: u32 = 2;
/// Nombre maximal de voies écrit par le noyau.
pub const MAX_PARALLELISM: u32 = 8;
/// Nombre minimal d'itérations écrit par le noyau.
pub const MIN_ITERATIONS: u64 = 4;
/// Nombre d'itérations par défaut, avant calibrage (environ 0,15 s sur un
/// serveur récent, 0,5 à 1 s sur un téléphone d'entrée de gamme).
pub const DEFAULT_ITERATIONS: u64 = 10;
/// Nombre maximal d'itérations écrit par le noyau (égal au plafond d'ouverture
/// par défaut, pour qu'un coffre écrit par le noyau se rouvre toujours).
pub const MAX_ITERATIONS: u64 = 1_000;
/// Plafond du calibrage automatique.
pub const MAX_CALIBRATED_ITERATIONS: u64 = 200;

/// Paramètres Argon2id d'un coffre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Mémoire, en octets.
    pub memory_bytes: u64,
    /// Nombre d'itérations.
    pub iterations: u64,
    /// Nombre de voies.
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_bytes: DEFAULT_MEMORY_BYTES,
            iterations: DEFAULT_ITERATIONS,
            parallelism: DEFAULT_PARALLELISM,
        }
    }
}

impl KdfParams {
    /// Vérifie que les paramètres respectent la politique.
    pub fn validate(&self) -> Result<()> {
        if !(MIN_MEMORY_BYTES..=MAX_MEMORY_BYTES).contains(&self.memory_bytes) {
            return Err(Error::InvalidInput(format!(
                "mémoire d'Argon2 : {} octets (accepté : 32 à 64 Mio)",
                self.memory_bytes
            )));
        }
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&self.iterations) {
            return Err(Error::InvalidInput(format!(
                "itérations d'Argon2 : {} (accepté : {MIN_ITERATIONS} à {MAX_ITERATIONS})",
                self.iterations
            )));
        }
        if !(1..=MAX_PARALLELISM).contains(&self.parallelism) {
            return Err(Error::InvalidInput(format!(
                "voies d'Argon2 : {} (accepté : 1 à {MAX_PARALLELISM})",
                self.parallelism
            )));
        }
        Ok(())
    }

    /// Configuration KDBX correspondante (Argon2id 1.3).
    pub fn to_config(self) -> KdfConfig {
        KdfConfig::Argon2id {
            iterations: self.iterations,
            memory: self.memory_bytes,
            parallelism: self.parallelism,
            version: argon2::Version::Version13,
        }
    }

    /// Calibre le nombre d'itérations pour qu'une ouverture dure environ
    /// `target` sur ce terminal, avec la mémoire et les voies par défaut.
    ///
    /// Sur ordinateur, viser une valeur plus courte que la cible souhaitée sur
    /// téléphone (un téléphone est souvent trois à cinq fois plus lent).
    pub fn calibrate(target: Duration) -> Result<Self> {
        const PROBE_ITERATIONS: u32 = 2;
        let memory_kib = u32::try_from(DEFAULT_MEMORY_BYTES / 1024)
            .map_err(|_| Error::InvalidInput("mémoire de calibrage".into()))?;
        let config = argon2::Config {
            ad: &[],
            hash_length: 32,
            lanes: DEFAULT_PARALLELISM,
            mem_cost: memory_kib,
            secret: &[],
            thread_mode: argon2::ThreadMode::Parallel,
            time_cost: PROBE_ITERATIONS,
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
        };
        let start = Instant::now();
        argon2::hash_raw(b"calibrage ligrivsstore", &[0u8; 32], &config)
            .map_err(|e| Error::InvalidInput(format!("calibrage d'Argon2 : {e}")))?;
        let per_iteration = start.elapsed().as_nanos() / u128::from(PROBE_ITERATIONS);
        let wanted = target.as_nanos() / per_iteration.max(1);
        let iterations = u64::try_from(wanted)
            .unwrap_or(u64::MAX)
            .clamp(MIN_ITERATIONS, MAX_CALIBRATED_ITERATIONS);
        Ok(Self {
            iterations,
            ..Self::default()
        })
    }
}

/// Paramètres à écrire à l'enregistrement, à partir de ceux du coffre ouvert.
///
/// - Argon2d ou Argon2id : passage en Argon2id, mémoire ramenée entre 32 et
///   64 Mio, itérations et voies ramenées dans les bornes de la politique ;
/// - AES-KDF (ancien) : remplacé par les paramètres par défaut.
pub fn normalize(existing: &KdfConfig) -> KdfConfig {
    match existing {
        KdfConfig::Argon2 {
            iterations,
            memory,
            parallelism,
            ..
        }
        | KdfConfig::Argon2id {
            iterations,
            memory,
            parallelism,
            ..
        } => KdfParams {
            memory_bytes: (*memory).clamp(MIN_MEMORY_BYTES, MAX_MEMORY_BYTES),
            iterations: (*iterations).clamp(MIN_ITERATIONS, MAX_ITERATIONS),
            parallelism: (*parallelism).clamp(1, MAX_PARALLELISM),
        }
        .to_config(),
        _ => KdfParams::default().to_config(),
    }
}

/// Description d'une configuration KDBX, dans les termes de [`Kdf`].
pub fn describe(config: &KdfConfig) -> Option<Kdf> {
    match config {
        KdfConfig::Aes { rounds } => Some(Kdf::Aes { rounds: *rounds }),
        KdfConfig::Argon2 {
            iterations,
            memory,
            parallelism,
            version,
        } => Some(Kdf::Argon2 {
            variant: Argon2Variant::Argon2d,
            memory_bytes: *memory,
            iterations: *iterations,
            parallelism: *parallelism,
            version: version.as_u32(),
        }),
        KdfConfig::Argon2id {
            iterations,
            memory,
            parallelism,
            version,
        } => Some(Kdf::Argon2 {
            variant: Argon2Variant::Argon2id,
            memory_bytes: *memory,
            iterations: *iterations,
            parallelism: *parallelism,
            version: version.as_u32(),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_respects_policy() {
        KdfParams::default().validate().unwrap();
        assert!(
            KdfParams {
                memory_bytes: 1 << 20,
                ..KdfParams::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn library_default_is_replaced() {
        // Valeurs par défaut de la bibliothèque : Argon2d, 1 Mio, 50 passes, 4 voies.
        let weak = KdfConfig::Argon2 {
            iterations: 50,
            memory: 1024 * 1024,
            parallelism: 4,
            version: argon2::Version::Version13,
        };
        assert_eq!(
            normalize(&weak),
            KdfConfig::Argon2id {
                iterations: 50,
                memory: MIN_MEMORY_BYTES,
                parallelism: 4,
                version: argon2::Version::Version13
            }
        );
    }

    #[test]
    fn aes_kdf_is_replaced_and_large_memory_is_capped() {
        assert_eq!(
            normalize(&KdfConfig::Aes { rounds: 60_000 }),
            KdfParams::default().to_config()
        );
        let heavy = KdfConfig::Argon2id {
            iterations: 2,
            memory: 512 * 1024 * 1024,
            parallelism: 64,
            version: argon2::Version::Version13,
        };
        assert_eq!(
            normalize(&heavy),
            KdfConfig::Argon2id {
                iterations: MIN_ITERATIONS,
                memory: MAX_MEMORY_BYTES,
                parallelism: MAX_PARALLELISM,
                version: argon2::Version::Version13
            }
        );
    }

    #[test]
    fn calibration_stays_in_bounds() {
        let params = KdfParams::calibrate(Duration::from_millis(200)).unwrap();
        assert!((MIN_ITERATIONS..=MAX_CALIBRATED_ITERATIONS).contains(&params.iterations));
        params.validate().unwrap();
    }
}
