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

/// Options du générateur de phrases de passe.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassphraseOptions {
    /// Nombre de mots (4 à 12).
    pub words: usize,
    /// Séparateur : tiret, espace, point ou soulignement.
    pub separator: String,
    /// Initiale de chaque mot en majuscule.
    pub capitalize: bool,
    /// Un chiffre accolé à un mot.
    pub digit: bool,
}

/// État observable, relu régulièrement par l'interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Activity {
    /// Un coffre est ouvert et déverrouillé.
    pub unlocked: bool,
    /// Motif du dernier verrouillage, à afficher.
    pub lock_message: Option<String>,
    /// Numéro qui change quand le contenu du coffre a changé hors de
    /// l'interface (fusion, restauration) : la liste doit être relue.
    pub revision: u64,
    /// Synchronisation.
    pub sync: SyncStatusView,
}

/// État de la synchronisation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatusView {
    /// Synchronisation réglée dans ce coffre.
    pub configured: bool,
    /// `non_configuree`, `en_attente`, `a_envoyer` (modifications
    /// enregistrées, pas encore envoyées), `en_cours`, `a_jour`,
    /// `hors_ligne`, `suspendue` ou `erreur`.
    pub state: &'static str,
    /// Dernier échange réussi (UTC, ISO 8601).
    pub last_success: Option<String>,
    /// Explication d'un échec.
    pub message: Option<String>,
}

/// Réglage de la synchronisation, tel qu'affiché (sans le mot de passe).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncSettingsView {
    /// Synchronisation réglée.
    pub configured: bool,
    /// Serveur (`https://coffre.ligrivs.com`).
    pub server: String,
    /// Compte WebDAV.
    pub account: String,
    /// Nom du coffre sur le serveur.
    pub file: String,
    /// Un mot de passe du serveur est enregistré.
    pub has_password: bool,
}

/// Demande de réglage de la synchronisation.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncSettingsRequest {
    /// Serveur.
    pub server: String,
    /// Compte WebDAV.
    pub account: String,
    /// Nom du coffre sur le serveur.
    pub file: String,
    /// Nouveau mot de passe du serveur ; absent pour garder l'actuel.
    pub password: Option<String>,
}

/// Demande d'installation, sur ce PC, du coffre présent sur le serveur.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallRequest {
    /// Serveur.
    pub server: String,
    /// Compte WebDAV.
    pub account: String,
    /// Nom du coffre sur le serveur.
    pub file: String,
    /// Mot de passe du serveur.
    pub server_password: String,
    /// Emplacement du coffre sur ce PC.
    pub path: String,
    /// Phrase de passe du coffre.
    pub passphrase: String,
    /// Fichier clé du coffre, s'il en a un.
    pub keyfile_path: Option<String>,
}

/// Une sauvegarde locale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupView {
    /// Identifiant : nom du fichier.
    pub id: String,
    /// Moment où cette version a été remplacée (UTC, ISO 8601).
    pub replaced: Option<String>,
    /// Taille, en octets.
    pub size: u64,
}

/// Bilan d'une restauration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreView {
    /// Entrées remises dans l'état de la sauvegarde.
    pub restored: usize,
    /// Entrées supprimées depuis, recréées.
    pub recreated: usize,
    /// Entrées identiques.
    pub unchanged: usize,
    /// Entrées écartées (champ trop long).
    pub skipped: usize,
}

/// Champ à copier dans le presse-papiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CopyField {
    /// Identifiant de connexion.
    Username,
    /// Mot de passe.
    Password,
}

/// Réglages de l'application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Preferences {
    /// Verrouillage après ce nombre de minutes d'inactivité (1 à 60).
    pub lock_minutes: u32,
    /// Effacement du presse-papiers après ce nombre de secondes (10 à 120).
    pub clipboard_seconds: u32,
}
