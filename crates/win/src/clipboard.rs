//! Presse-papiers protégé.
//!
//! Le secret est déposé avec trois formats que Windows lit avant de le
//! conserver ailleurs :
//!
//! - `ExcludeClipboardContentFromMonitorProcessing` : contenu ignoré par les
//!   programmes qui surveillent le presse-papiers ;
//! - `CanIncludeInClipboardHistory` à 0 : absent de l'historique (Windows + V) ;
//! - `CanUploadToCloudClipboard` à 0 : jamais envoyé au presse-papiers cloud.
//!
//! Ces formats sont posés avant le texte : si l'un échoue, rien n'est copié.
//! L'application efface ensuite le presse-papiers après un délai, s'il
//! contient toujours sa copie ([`clear_if_unchanged`]) : on n'efface jamais ce
//! qu'un autre programme y a mis entre-temps.

use crate::WinError;

/// Formats Windows qui tiennent un contenu hors de l'historique et du cloud,
/// avec leur valeur (un entier de 32 bits).
pub const PROTECTION_FORMATS: [(&str, u32); 3] = [
    ("ExcludeClipboardContentFromMonitorProcessing", 1),
    ("CanIncludeInClipboardHistory", 0),
    ("CanUploadToCloudClipboard", 0),
];

/// Repère d'une copie : numéro de séquence du presse-papiers juste après.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyToken(u32);

/// Copie `text` dans le presse-papiers, hors de l'historique et du cloud.
pub fn copy_protected(text: &str) -> Result<CopyToken, WinError> {
    #[cfg(windows)]
    {
        windows::copy_protected(text)
    }
    #[cfg(not(windows))]
    {
        let _ = text;
        Err(WinError::Unsupported)
    }
}

/// Vide le presse-papiers s'il contient toujours la copie repérée par
/// `token`. Renvoie `true` s'il a été vidé.
pub fn clear_if_unchanged(token: CopyToken) -> Result<bool, WinError> {
    #[cfg(windows)]
    {
        windows::clear_if_unchanged(token)
    }
    #[cfg(not(windows))]
    {
        let _ = token;
        Ok(false)
    }
}

#[cfg(windows)]
mod windows {
    use std::num::NonZeroU32;

    use clipboard_win::{Clipboard, options::NoClear, raw};

    use super::{CopyToken, PROTECTION_FORMATS};
    use crate::WinError;

    /// Tentatives d'ouverture : un autre programme peut tenir le presse-papiers
    /// quelques millisecondes.
    const ATTEMPTS: usize = 20;

    pub(super) fn copy_protected(text: &str) -> Result<CopyToken, WinError> {
        let mut formats = Vec::with_capacity(PROTECTION_FORMATS.len());
        for (name, value) in PROTECTION_FORMATS {
            let format = raw::register_format(name)
                .ok_or_else(|| WinError::Clipboard(format!("format {name} non enregistré")))?;
            formats.push((format.get(), value));
        }
        {
            let _open = Clipboard::new_attempts(ATTEMPTS).map_err(error)?;
            raw::empty().map_err(error)?;
            for (format, value) in formats {
                raw::set_without_clear(format, &value.to_le_bytes()).map_err(error)?;
            }
            if let Err(e) = raw::set_string_with(text, NoClear) {
                let _ = raw::empty();
                return Err(error(e));
            }
        }
        Ok(CopyToken(sequence()))
    }

    pub(super) fn clear_if_unchanged(token: CopyToken) -> Result<bool, WinError> {
        if token.0 == 0 || sequence() != token.0 {
            return Ok(false);
        }
        // Presse-papiers ouvert, plus personne ne peut le modifier : on revérifie.
        let _open = Clipboard::new_attempts(ATTEMPTS).map_err(error)?;
        if sequence() != token.0 {
            return Ok(false);
        }
        raw::empty().map_err(error)?;
        Ok(true)
    }

    fn sequence() -> u32 {
        raw::seq_num().map_or(0, NonZeroU32::get)
    }

    fn error(e: impl std::fmt::Display) -> WinError {
        WinError::Clipboard(e.to_string())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn read_u32(name: &str) -> Option<u32> {
            let format = raw::register_format(name)?.get();
            let _open = Clipboard::new_attempts(ATTEMPTS).ok()?;
            let mut buffer = [0u8; 4];
            let read = raw::get(format, &mut buffer).ok()?;
            (read == 4).then(|| u32::from_le_bytes(buffer))
        }

        // Un seul essai touche au presse-papiers du système, partagé par tous
        // les essais du processus.
        #[test]
        fn protected_copy_then_clear_only_our_own_copy() {
            let token = copy_protected("secret-d-essai-é").unwrap();
            assert_eq!(
                clipboard_win::get_clipboard_string().unwrap(),
                "secret-d-essai-é"
            );
            for (name, value) in PROTECTION_FORMATS {
                assert_eq!(read_u32(name), Some(value), "{name}");
            }
            assert!(clear_if_unchanged(token).unwrap());
            assert!(clipboard_win::get_clipboard_string().is_err());
            // Déjà vidé : rien à faire.
            assert!(!clear_if_unchanged(token).unwrap());

            // Un autre programme copie entre-temps : sa copie est conservée.
            let token = copy_protected("deuxième secret").unwrap();
            clipboard_win::set_clipboard_string("copie d'un autre programme").unwrap();
            assert!(!clear_if_unchanged(token).unwrap());
            assert_eq!(
                clipboard_win::get_clipboard_string().unwrap(),
                "copie d'un autre programme"
            );
            let _open = Clipboard::new_attempts(ATTEMPTS).unwrap();
            raw::empty().unwrap();
        }
    }
}
