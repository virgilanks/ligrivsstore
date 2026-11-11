//! Robustesse des phrases de passe (estimation zxcvbn).

use crate::dto::Strength;

/// Longueur minimale d'une phrase de passe de coffre, en caractères.
pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// Score zxcvbn minimal (sur 4) pour créer un coffre.
const MIN_SCORE: u8 = 3;

/// Estime la robustesse d'une phrase de passe.
///
/// Une phrase est acceptée pour un coffre si elle compte au moins
/// [`MIN_PASSPHRASE_CHARS`] caractères et obtient au moins 3 sur 4 : de
/// l'ordre de 10¹⁰ essais au minimum selon zxcvbn, avant même le coût
/// d'Argon2id pour chaque essai.
pub fn passphrase_strength(passphrase: &str) -> Strength {
    let chars = passphrase.chars().count();
    if passphrase.is_empty() {
        return Strength {
            score: 0,
            label: label(0),
            acceptable: false,
            guesses_log10: 0.0,
            too_short: true,
        };
    }
    let estimate = zxcvbn::zxcvbn(passphrase, &["ligrivsstore", "keepass", "coffre"]);
    let score = u8::from(estimate.score());
    let too_short = chars < MIN_PASSPHRASE_CHARS;
    Strength {
        score,
        label: label(score),
        acceptable: !too_short && score >= MIN_SCORE,
        guesses_log10: estimate.guesses_log10(),
        too_short,
    }
}

fn label(score: u8) -> &'static str {
    match score {
        0 => "très faible",
        1 => "faible",
        2 => "moyenne",
        3 => "bonne",
        _ => "excellente",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_or_short_passphrases_are_refused() {
        assert!(!passphrase_strength("").acceptable);
        assert!(!passphrase_strength("motdepasse").acceptable);
        assert!(!passphrase_strength("Azerty123!").acceptable);
        let short = passphrase_strength("x7#Kq!9z");
        assert!(short.too_short && !short.acceptable);
    }

    #[test]
    fn a_long_random_passphrase_is_accepted() {
        let strength = passphrase_strength("corail-prisme-vélo-tonnerre-anis");
        assert!(strength.acceptable, "{strength:?}");
        assert!(strength.score >= 3);
        assert!(strength.guesses_log10 > 10.0);
    }

    #[test]
    fn the_product_name_does_not_make_a_passphrase_strong() {
        let strength = passphrase_strength("ligrivsstore2026");
        assert!(!strength.acceptable, "{strength:?}");
    }
}
