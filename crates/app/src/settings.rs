//! Réglages de l'application : le dernier coffre ouvert, l'emplacement de son
//! fichier clé, le délai de verrouillage et celui d'effacement du
//! presse-papiers.
//!
//! Aucun secret n'y figure. Le fichier est `reglages.json`, dans le dossier
//! de configuration de l'utilisateur ; un fichier illisible est remplacé par
//! des réglages vides, sans bloquer l'application.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Nom du fichier des réglages.
pub const FILE_NAME: &str = "reglages.json";

/// Délai de verrouillage par défaut, en minutes d'inactivité.
pub const DEFAULT_LOCK_MINUTES: u32 = 5;
/// Délais de verrouillage admis.
pub const LOCK_MINUTES: std::ops::RangeInclusive<u32> = 1..=60;
/// Délai d'effacement du presse-papiers par défaut, en secondes.
pub const DEFAULT_CLIPBOARD_SECONDS: u32 = 30;
/// Délais d'effacement admis.
pub const CLIPBOARD_SECONDS: std::ops::RangeInclusive<u32> = 10..=120;

/// Réglages enregistrés.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Settings {
    /// Dernier coffre ouvert ou créé.
    pub last_vault: Option<PathBuf>,
    /// Fichier clé de ce coffre, s'il en a un.
    pub last_keyfile: Option<PathBuf>,
    /// Verrouillage après ce nombre de minutes d'inactivité.
    pub lock_minutes: u32,
    /// Effacement du presse-papiers après ce nombre de secondes.
    pub clipboard_seconds: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            last_vault: None,
            last_keyfile: None,
            lock_minutes: DEFAULT_LOCK_MINUTES,
            clipboard_seconds: DEFAULT_CLIPBOARD_SECONDS,
        }
    }
}

impl Settings {
    /// Lit les réglages ; renvoie des réglages vides si le fichier manque ou
    /// est illisible. Les délais hors des bornes y sont ramenés.
    pub fn load(path: &Path) -> Self {
        let mut settings: Self = std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        settings.lock_minutes = settings
            .lock_minutes
            .clamp(*LOCK_MINUTES.start(), *LOCK_MINUTES.end());
        settings.clipboard_seconds = settings
            .clipboard_seconds
            .clamp(*CLIPBOARD_SECONDS.start(), *CLIPBOARD_SECONDS.end());
        settings
    }

    /// Enregistre les réglages (écriture atomique).
    pub fn save(&self, path: &Path) -> ligrivsstore_core::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| ligrivsstore_core::Error::Save(format!("réglages : {e}")))?;
        ligrivsstore_core::storage::replace_file(path, &json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_round_trip_and_survive_a_damaged_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config").join(FILE_NAME);
        assert_eq!(Settings::load(&path), Settings::default());
        let settings = Settings {
            last_vault: Some(dir.path().join("coffre.kdbx")),
            last_keyfile: None,
            lock_minutes: 12,
            clipboard_seconds: 45,
        };
        settings.save(&path).unwrap();
        assert_eq!(Settings::load(&path), settings);
        std::fs::write(&path, b"{ pas du json").unwrap();
        assert_eq!(Settings::load(&path), Settings::default());
    }

    #[test]
    fn older_files_get_default_delays_and_odd_values_are_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        std::fs::write(&path, br#"{"lastVault":"C:/coffre.kdbx"}"#).unwrap();
        let settings = Settings::load(&path);
        assert_eq!(settings.lock_minutes, DEFAULT_LOCK_MINUTES);
        assert_eq!(settings.clipboard_seconds, DEFAULT_CLIPBOARD_SECONDS);
        std::fs::write(&path, br#"{"lockMinutes":0,"clipboardSeconds":100000}"#).unwrap();
        let settings = Settings::load(&path);
        assert_eq!(settings.lock_minutes, 1);
        assert_eq!(settings.clipboard_seconds, 120);
    }
}
