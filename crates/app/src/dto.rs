//! Messages échangés avec l'interface, sérialisés en JSON.
//!
//! Les noms des champs suivent la convention de JavaScript (`camelCase`). Les
//! phrases de passe et mots de passe reçus sont placés aussitôt dans une
//! mémoire effacée à la destruction (`Zeroizing`) par la [`Session`](crate::Session).

use serde::{Deserialize, Serialize};

/// État de l'application.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    /// Un coffre est ouvert et déverrouillé.
    pub unlocked: bool,
    /// Coffre ouvert, ou dernier coffre utilisé.
    pub vault_path: Option<String>,
    /// Fichier clé de ce coffre, s'il en a un.
    pub keyfile_path: Option<String>,
    /// Nom du coffre ouvert.
    pub vault_name: Option<String>,
    /// Nombre d'entrées du coffre ouvert.
    pub entry_count: usize,
    /// Des modifications n'ont pas pu être enregistrées sur le disque.
    pub unsaved: bool,
}

/// Emplacements proposés à la création d'un coffre.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DefaultPaths {
    /// Coffre (dans les documents de l'utilisateur).
    pub vault: String,
    /// Fichier clé (dans les données locales de l'application, jamais
    /// synchronisées par OneDrive).
    pub keyfile: String,
}

/// Fichier clé choisi à la création d'un coffre.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum KeyfileChoice {
    /// Phrase de passe seule.
    None,
    /// Fichier clé existant.
    Existing {
        /// Emplacement du fichier.
        path: String,
    },
    /// Nouveau fichier clé, créé au format XML 2.0 de KeePass.
    Generate {
        /// Emplacement du fichier à créer.
        path: String,
    },
}

/// Demande de création d'un coffre.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateVaultRequest {
    /// Fichier du coffre à créer.
    pub path: String,
    /// Nom du coffre.
    pub name: String,
    /// Phrase de passe.
    pub passphrase: String,
    /// Fichier clé.
    pub keyfile: KeyfileChoice,
}

/// Demande d'ouverture d'un coffre.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenVaultRequest {
    /// Fichier du coffre.
    pub path: String,
    /// Phrase de passe (vide pour un coffre protégé par un fichier clé seul).
    pub passphrase: String,
    /// Fichier clé, s'il y en a un.
    pub keyfile_path: Option<String>,
}

/// Ligne de la liste des entrées, sans mot de passe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryRow {
    /// Identifiant de l'entrée.
    pub id: String,
    /// Titre.
    pub title: String,
    /// Identifiant de connexion ou adresse e-mail.
    pub username: String,
    /// Adresse du site, serveur ou application.
    pub url: String,
}

/// Fiche d'une entrée, sans le mot de passe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryView {
    /// Identifiant de l'entrée.
    pub id: String,
    /// Titre.
    pub title: String,
    /// Adresse du site, serveur ou application.
    pub url: String,
    /// Identifiant de connexion ou adresse e-mail.
    pub username: String,
    /// Notes.
    pub notes: String,
    /// Un mot de passe est enregistré.
    pub has_password: bool,
    /// Dernière modification (UTC, ISO 8601).
    pub modified: Option<String>,
    /// Nombre de versions antérieures conservées.
    pub history_len: usize,
}

/// Demande d'enregistrement d'une entrée (création ou modification).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveEntryRequest {
    /// Entrée à modifier ; absent pour une nouvelle entrée.
    pub id: Option<String>,
    /// Titre.
    pub title: String,
    /// Adresse.
    pub url: String,
    /// Identifiant de connexion.
    pub username: String,
    /// Nouveau mot de passe ; absent pour garder l'actuel.
    pub password: Option<String>,
    /// Notes.
    pub notes: String,
}

/// Options du générateur de mots de passe.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratorOptions {
    /// Longueur (8 à 128).
    pub length: usize,
    /// Minuscules.
    pub lowercase: bool,
    /// Majuscules.
    pub uppercase: bool,
    /// Chiffres.
    pub digits: bool,
    /// Symboles.
    pub symbols: bool,
    /// Sans caractères faciles à confondre (0, O, 1, l…).
    pub exclude_ambiguous: bool,
}

/// Mot de passe généré.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Generated {
    /// Mot de passe.
    pub password: String,
    /// Entropie, en bits.
    pub entropy_bits: f64,
}

impl std::fmt::Debug for Generated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Generated")
            .field("password", &"<masqué>")
            .field("entropy_bits", &self.entropy_bits)
            .finish()
    }
}

impl Drop for Generated {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.password);
    }
}

/// Robustesse estimée d'une phrase de passe.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Strength {
    /// Score de 0 à 4.
    pub score: u8,
    /// Libellé en français.
    pub label: &'static str,
    /// Assez robuste pour protéger un coffre.
    pub acceptable: bool,
    /// Logarithme décimal du nombre d'essais estimé.
    pub guesses_log10: f64,
    /// Moins de 12 caractères.
    pub too_short: bool,
}
