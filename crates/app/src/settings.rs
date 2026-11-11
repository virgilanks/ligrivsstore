//! Réglages de l'application : le dernier coffre ouvert et l'emplacement de
//! son fichier clé.
//!
//! Aucun secret n'y figure. Le fichier est `reglages.json`, dans le dossier
//! de configuration de l'utilisateur ; un fichier illisible est remplacé par
//! des réglages vides, sans bloquer l'application.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Nom du fichier des réglages.
pub const FILE_NAME: &str = "reglages.json";

/// Réglages enregistrés.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Settings {
    /// Dernier coffre ouvert ou créé.
    pub last_vault: Option<PathBuf>,
    /// Fichier clé de ce coffre, s'il en a un.
    pub last_keyfile: Option<PathBuf>,
}

impl Settings {
    /// Lit les réglages ; renvoie des réglages vides si le fichier manque ou
    /// est illisible.
    pub fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
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
        };
        settings.save(&path).unwrap();
        assert_eq!(Settings::load(&path), settings);
        std::fs::write(&path, b"{ pas du json").unwrap();
        assert_eq!(Settings::load(&path), Settings::default());
    }
}
