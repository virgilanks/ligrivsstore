//! Générateur de mots de passe et de phrases de passe.
//!
//! Chaque caractère ou mot est tiré par le générateur aléatoire du système
//! d'exploitation, par tirage avec rejet (aucun biais de modulo).
//!
//! - Mot de passe : au moins un caractère de chaque famille demandée, puis
//!   mélange (Fisher-Yates).
//! - Phrase de passe : mots de la liste longue de l'EFF (7 776 mots, soit
//!   12,9 bits par mot), séparés par un caractère au choix (décision D8 ; voir
//!   `data/LISEZMOI.md` pour l'origine et la licence de la liste).

use std::sync::OnceLock;

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

/// Liste longue de l'EFF (2016), telle que publiée : cinq chiffres de dé, une
/// tabulation, le mot.
const EFF_LARGE_WORDLIST: &str = include_str!("../data/eff_large_wordlist.txt");
/// Nombre de mots de la liste (6⁵).
pub const WORDLIST_LEN: usize = 7_776;
/// Nombre minimal de mots d'une phrase de passe.
pub const MIN_WORDS: usize = 4;
/// Nombre maximal de mots d'une phrase de passe.
pub const MAX_WORDS: usize = 12;
/// Séparateurs admis entre les mots.
pub const SEPARATORS: [char; 4] = ['-', ' ', '.', '_'];

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

/// Règles de génération d'une phrase de passe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassphrasePolicy {
    /// Nombre de mots.
    pub words: usize,
    /// Séparateur, parmi [`SEPARATORS`].
    pub separator: char,
    /// Initiale de chaque mot en majuscule (n'ajoute pas d'entropie).
    pub capitalize: bool,
    /// Un chiffre au hasard, accolé à un mot pris au hasard (certains sites
    /// exigent un chiffre).
    pub digit: bool,
}

impl Default for PassphrasePolicy {
    fn default() -> Self {
        Self {
            words: 6,
            separator: '-',
            capitalize: false,
            digit: false,
        }
    }
}

impl PassphrasePolicy {
    /// Entropie, en bits : nombre de mots × log2(7 776), plus log2(10 × nombre
    /// de mots) pour le chiffre (sa valeur et le mot qui le porte).
    pub fn entropy_bits(&self) -> f64 {
        #[allow(clippy::cast_precision_loss)]
        let words = self.words as f64;
        #[allow(clippy::cast_precision_loss)]
        let per_word = (WORDLIST_LEN as f64).log2();
        let digit = if self.digit && self.words > 0 {
            (10.0 * words).log2()
        } else {
            0.0
        };
        words * per_word + digit
    }
}

/// Mots de la liste de l'EFF, dans l'ordre de publication.
pub fn wordlist() -> Result<&'static [&'static str]> {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    let words = WORDS.get_or_init(|| {
        EFF_LARGE_WORDLIST
            .lines()
            .filter_map(|line| line.split_once('\t').map(|(_, word)| word))
            .collect()
    });
    if words.len() == WORDLIST_LEN {
        Ok(words)
    } else {
        Err(Error::InvalidInput("liste de mots altérée".into()))
    }
}

/// Génère une phrase de passe selon `policy`.
pub fn generate_passphrase(policy: &PassphrasePolicy) -> Result<Zeroizing<String>> {
    if !(MIN_WORDS..=MAX_WORDS).contains(&policy.words) {
        return Err(Error::InvalidInput(format!(
            "{} mots (acceptés : {MIN_WORDS} à {MAX_WORDS})",
            policy.words
        )));
    }
    if !SEPARATORS.contains(&policy.separator) {
        return Err(Error::InvalidInput(
            "séparateur refusé : tiret, espace, point ou soulignement".into(),
        ));
    }
    let list = wordlist()?;
    let digit = if policy.digit {
        let position = uniform(policy.words)?;
        let value = u32::try_from(uniform(10)?).map_err(|_| Error::Random)?;
        Some((position, char::from_digit(value, 10).ok_or(Error::Random)?))
    } else {
        None
    };
    let mut phrase = Zeroizing::new(String::with_capacity(policy.words * 10));
    for index in 0..policy.words {
        if index > 0 {
            phrase.push(policy.separator);
        }
        let word = list.get(uniform(list.len())?).ok_or(Error::Random)?;
        let mut chars = word.chars();
        if policy.capitalize
            && let Some(first) = chars.next()
        {
            phrase.extend(first.to_uppercase());
            phrase.push_str(chars.as_str());
        } else {
            phrase.push_str(word);
        }
        if let Some((position, value)) = digit
            && position == index
        {
            phrase.push(value);
        }
    }
    Ok(phrase)
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

    #[test]
    fn embedded_wordlist_is_the_published_eff_list() {
        use sha2::{Digest, Sha256};
        // Empreinte du fichier publié par l'EFF
        // (https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt).
        assert_eq!(
            hex::encode(Sha256::digest(EFF_LARGE_WORDLIST.as_bytes())),
            "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"
        );
        let words = wordlist().unwrap();
        assert_eq!(words.len(), WORDLIST_LEN);
        let unique: std::collections::BTreeSet<_> = words.iter().collect();
        assert_eq!(unique.len(), WORDLIST_LEN);
        assert!(
            words.iter().all(|w| (3..=9).contains(&w.len())
                && w.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
        );
        assert_eq!(words.first(), Some(&"abacus"));
        assert_eq!(words.last(), Some(&"zoom"));
    }

    #[test]
    fn passphrases_follow_the_policy() {
        let list = wordlist().unwrap();
        for words in [MIN_WORDS, 6, MAX_WORDS] {
            for capitalize in [false, true] {
                for digit in [false, true] {
                    let policy = PassphrasePolicy {
                        words,
                        separator: ' ',
                        capitalize,
                        digit,
                    };
                    let phrase = generate_passphrase(&policy).unwrap();
                    let parts: Vec<&str> = phrase.split(' ').collect();
                    assert_eq!(parts.len(), words, "{}", phrase.as_str());
                    let digits = phrase.chars().filter(char::is_ascii_digit).count();
                    assert_eq!(digits, usize::from(digit));
                    for part in parts {
                        let bare: String = part
                            .chars()
                            .filter(|c| !c.is_ascii_digit())
                            .collect::<String>()
                            .to_lowercase();
                        assert!(list.contains(&bare.as_str()), "{part}");
                        let first = part.chars().next().unwrap();
                        assert_eq!(first.is_ascii_uppercase(), capitalize, "{part}");
                    }
                }
            }
        }
    }

    #[test]
    fn passphrase_entropy() {
        let six = PassphrasePolicy::default().entropy_bits();
        assert!((77.5..77.6).contains(&six), "{six}");
        let with_digit = PassphrasePolicy {
            digit: true,
            ..PassphrasePolicy::default()
        }
        .entropy_bits();
        assert!((83.4..83.5).contains(&with_digit), "{with_digit}");
    }

    #[test]
    fn refuses_invalid_passphrase_policies() {
        for words in [0, MIN_WORDS - 1, MAX_WORDS + 1] {
            let policy = PassphrasePolicy {
                words,
                ..PassphrasePolicy::default()
            };
            assert!(generate_passphrase(&policy).is_err());
        }
        let letter = PassphrasePolicy {
            separator: 'a',
            ..PassphrasePolicy::default()
        };
        assert!(generate_passphrase(&letter).is_err());
    }

    #[test]
    fn passphrases_differ() {
        let policy = PassphrasePolicy::default();
        let a = generate_passphrase(&policy).unwrap();
        let b = generate_passphrase(&policy).unwrap();
        assert_ne!(a.as_str(), b.as_str());
    }
}
