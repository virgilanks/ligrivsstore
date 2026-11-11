//! Générateur de mots de passe.
//!
//! Chaque caractère est tiré par le générateur aléatoire du système
//! d'exploitation, par tirage avec rejet (aucun biais de modulo). Le mot de
//! passe contient au moins un caractère de chaque famille demandée, puis est
//! mélangé (Fisher-Yates).

use zeroize::Zeroizing;

use crate::error::{Error, Result};

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
/// Symboles acceptés par la plupart des formulaires (ni espace, ni guillemets,
/// ni barre oblique inverse, ni accent grave).
const SYMBOLS: &[u8] = b"!#$%&()*+,-./:;<=>?@[]^_{|}~";
/// Caractères faciles à confondre à la lecture.
const AMBIGUOUS: &[u8] = b"Il1O0o|";

/// Longueur minimale.
pub const MIN_LENGTH: usize = 8;
/// Longueur maximale.
pub const MAX_LENGTH: usize = 128;

/// Règles de génération.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordPolicy {
    /// Nombre de caractères.
    pub length: usize,
    /// Lettres minuscules.
    pub lowercase: bool,
    /// Lettres majuscules.
    pub uppercase: bool,
    /// Chiffres.
    pub digits: bool,
    /// Symboles.
    pub symbols: bool,
    /// Écarter les caractères faciles à confondre (I, l, 1, O, 0, o, |).
    pub exclude_ambiguous: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

impl PasswordPolicy {
    fn families(&self) -> Vec<Vec<u8>> {
        [
            (self.lowercase, LOWERCASE),
            (self.uppercase, UPPERCASE),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ]
        .into_iter()
        .filter(|(wanted, _)| *wanted)
        .map(|(_, set)| {
            set.iter()
                .copied()
                .filter(|c| !self.exclude_ambiguous || !AMBIGUOUS.contains(c))
                .collect()
        })
        .collect()
    }

    /// Entropie approximative, en bits (longueur × log2 de l'alphabet).
    pub fn entropy_bits(&self) -> f64 {
        let alphabet: usize = self.families().iter().map(Vec::len).sum();
        if alphabet == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let bits = self.length as f64 * (alphabet as f64).log2();
        bits
    }
}

/// Génère un mot de passe selon `policy`.
pub fn generate_password(policy: &PasswordPolicy) -> Result<Zeroizing<String>> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&policy.length) {
        return Err(Error::InvalidInput(format!(
            "longueur {} (acceptée : {MIN_LENGTH} à {MAX_LENGTH})",
            policy.length
        )));
    }
    let families = policy.families();
    if families.is_empty() {
        return Err(Error::InvalidInput(
            "choisir au moins une famille de caractères".into(),
        ));
    }
    let alphabet: Vec<u8> = families.concat();
    let mut chars: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(policy.length));
    for family in &families {
        chars.push(pick(family)?);
    }
    while chars.len() < policy.length {
        chars.push(pick(&alphabet)?);
    }
    for i in (1..chars.len()).rev() {
        let j = uniform(i + 1)?;
        chars.swap(i, j);
    }
    let mut password = Zeroizing::new(String::with_capacity(chars.len()));
    for &c in chars.iter() {
        password.push(char::from(c));
    }
    Ok(password)
}

fn pick(set: &[u8]) -> Result<u8> {
    let index = uniform(set.len())?;
    set.get(index).copied().ok_or(Error::Random)
}

/// Entier uniforme dans `[0, n)`, par tirage avec rejet.
fn uniform(n: usize) -> Result<usize> {
    let n = u32::try_from(n).map_err(|_| Error::InvalidInput("ensemble trop grand".into()))?;
    if n == 0 {
        return Err(Error::InvalidInput("ensemble vide".into()));
    }
    let zone = (u32::MAX / n) * n;
    loop {
        let value = getrandom::u32().map_err(|_| Error::Random)?;
        if value < zone {
            return usize::try_from(value % n).map_err(|_| Error::Random);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_length_and_families() {
        for length in [MIN_LENGTH, 20, MAX_LENGTH] {
            let policy = PasswordPolicy {
                length,
                ..PasswordPolicy::default()
            };
            for _ in 0..50 {
                let password = generate_password(&policy).unwrap();
                let bytes = password.as_bytes();
                assert_eq!(bytes.len(), length);
                assert!(bytes.iter().any(|c| LOWERCASE.contains(c)));
                assert!(bytes.iter().any(|c| UPPERCASE.contains(c)));
                assert!(bytes.iter().any(|c| DIGITS.contains(c)));
                assert!(bytes.iter().any(|c| SYMBOLS.contains(c)));
            }
        }
    }

    #[test]
    fn excludes_ambiguous_characters() {
        let policy = PasswordPolicy {
            length: MAX_LENGTH,
            exclude_ambiguous: true,
            ..PasswordPolicy::default()
        };
        for _ in 0..50 {
            let password = generate_password(&policy).unwrap();
            assert!(!password.bytes().any(|c| AMBIGUOUS.contains(&c)));
        }
    }

    #[test]
    fn refuses_invalid_policies() {
        let none = PasswordPolicy {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..PasswordPolicy::default()
        };
        assert!(generate_password(&none).is_err());
        let short = PasswordPolicy {
            length: 4,
            ..PasswordPolicy::default()
        };
        assert!(generate_password(&short).is_err());
    }

    #[test]
    fn draws_are_roughly_uniform() {
        let mut counts = [0usize; 10];
        let draws = 100_000;
        for _ in 0..draws {
            counts[uniform(10).unwrap()] += 1;
        }
        // Écart toléré : 5 % (environ 16 écarts-types pour 10 000 tirages attendus).
        for count in counts {
            assert!((9_500..=10_500).contains(&count), "{counts:?}");
        }
    }

    #[test]
    fn entropy_of_default_policy() {
        let bits = PasswordPolicy::default().entropy_bits();
        assert!(bits > 120.0, "{bits}");
    }
}
