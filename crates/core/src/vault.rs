//! Coffre KDBX 4 : création, ouverture, enregistrement, entrées, fusion.
//!
//! La lecture et l'écriture du format reposent sur la bibliothèque `keepass`
//! (licence MIT), version épinglée. Ce module l'encadre :
//! - l'en-tête est contrôlé avant toute dérivation de clé ([`crate::header`]) ;
//! - une lecture qui échoue brutalement est convertie en erreur, sans arrêter
//!   l'application ;
//! - l'enregistrement se fait toujours en KDBX 4.1, avec nos paramètres de
//!   dérivation ([`crate::kdf`]) ;
//! - chaque modification d'une entrée porte un horodatage strictement croissant :
//!   le format est à la seconde, et deux versions de même date ne peuvent pas
//!   être ordonnées lors d'une fusion (la bibliothèque garde alors l'une et
//!   range l'autre dans l'historique, avec un avertissement).

use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};

use chrono::{NaiveDateTime, TimeDelta};
use keepass::DatabaseKey;
use keepass::config::{
    CompressionConfig, DatabaseConfig, DatabaseVersion, InnerCipherConfig, OuterCipherConfig,
};
use keepass::db::merge::{MergeEventType, MergeLog};
use keepass::db::{Database, EntryId, EntryRef, History, Times, fields};
use keepass::error::{DatabaseKeyError, DatabaseOpenError};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::header::{self, Kdf, OpenLimits};
use crate::kdf::{self, KdfParams};

/// Nombre de versions conservées par entrée quand le coffre ne fixe rien
/// (valeur par défaut de KeePass).
const DEFAULT_HISTORY_ITEMS: usize = 10;

/// Longueurs maximales acceptées pour les champs d'une entrée.
const MAX_SHORT_FIELD: usize = 4 * 1024;
const MAX_URL: usize = 16 * 1024;
const MAX_NOTES: usize = 1024 * 1024;

/// Clé d'un coffre : phrase de passe, fichier clé, ou les deux.
///
/// Son contenu est effacé de la mémoire à sa destruction et n'apparaît jamais
/// dans les journaux (affichage masqué).
#[derive(Clone, Default)]
pub struct VaultKey {
    inner: DatabaseKey,
}

impl VaultKey {
    /// Clé vide, à compléter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ajoute la phrase de passe.
    pub fn with_password(self, password: &str) -> Self {
        Self {
            inner: self.inner.with_password(password),
        }
    }

    /// Ajoute le contenu du fichier clé (formats XML de KeePass, 32 octets,
    /// 64 caractères hexadécimaux, ou tout autre fichier, alors haché).
    ///
    /// Un fichier XML 2.0 dont la somme de contrôle ne correspond pas est
    /// refusé ([`Error::KeyFileCorrupt`](crate::Error::KeyFileCorrupt)), comme
    /// dans KeePassXC.
    pub fn with_keyfile(self, keyfile: &[u8]) -> Result<Self> {
        crate::keyfile::verify_checksum(keyfile)?;
        let mut reader = keyfile;
        Ok(Self {
            inner: self.inner.with_keyfile(&mut reader)?,
        })
    }

    /// Vrai si la clé ne contient encore aucun élément.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub(crate) fn database_key(&self) -> DatabaseKey {
        self.inner.clone()
    }
}

impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultKey(<masquée>)")
    }
}

/// Champs saisis pour une entrée.
#[derive(Clone, Default)]
pub struct EntryInput {
    /// Titre (obligatoire).
    pub title: String,
    /// Adresse du site, serveur ou application.
    pub url: String,
    /// Identifiant ou adresse e-mail.
    pub username: String,
    /// Mot de passe (effacé de la mémoire à la destruction).
    pub password: Zeroizing<String>,
    /// Notes.
    pub notes: String,
}

impl EntryInput {
    /// Vérifie les champs saisis.
    pub fn validate(&self) -> Result<()> {
        if self.title.trim().is_empty() {
            return Err(Error::InvalidInput("le titre est obligatoire".into()));
        }
        let checks = [
            ("titre", self.title.len(), MAX_SHORT_FIELD),
            ("identifiant", self.username.len(), MAX_SHORT_FIELD),
            ("mot de passe", self.password.len(), MAX_SHORT_FIELD),
            ("adresse", self.url.len(), MAX_URL),
            ("notes", self.notes.len(), MAX_NOTES),
        ];
        for (name, length, max) in checks {
            if length > max {
                return Err(Error::InvalidInput(format!(
                    "{name} trop long : {length} octets (maximum {max})"
                )));
            }
        }
        Ok(())
    }
}

impl fmt::Debug for EntryInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryInput")
            .field("title", &self.title)
            .field("url", &self.url)
            .field("username", &self.username)
            .field("password", &"<masqué>")
            .field("notes", &format_args!("<{} octets>", self.notes.len()))
            .finish()
    }
}

/// Résumé d'une entrée, sans le mot de passe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrySummary {
    /// Identifiant (UUID).
    pub id: String,
    /// Titre.
    pub title: String,
    /// Adresse du site, serveur ou application.
    pub url: String,
    /// Identifiant ou adresse e-mail.
    pub username: String,
    /// Date de dernière modification (UTC, ISO 8601).
    pub modified: Option<String>,
}

/// Détail d'une entrée, mot de passe compris.
#[derive(Clone)]
pub struct EntryDetails {
    /// Identifiant (UUID).
    pub id: String,
    /// Titre.
    pub title: String,
    /// Adresse du site, serveur ou application.
    pub url: String,
    /// Identifiant ou adresse e-mail.
    pub username: String,
    /// Mot de passe (effacé de la mémoire à la destruction).
    pub password: Zeroizing<String>,
    /// Notes.
    pub notes: String,
    /// Date de dernière modification (UTC, ISO 8601).
    pub modified: Option<String>,
    /// Nombre de versions antérieures conservées.
    pub history_len: usize,
}

impl fmt::Debug for EntryDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryDetails")
            .field("id", &self.id)
            .field("title", &self.title)
            .field("url", &self.url)
            .field("username", &self.username)
            .field("password", &"<masqué>")
            .field("modified", &self.modified)
            .field("history_len", &self.history_len)
            .finish_non_exhaustive()
    }
}

/// Bilan d'une fusion.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// Objets (entrées, groupes, icônes) ajoutés.
    pub created: usize,
    /// Objets mis à jour.
    pub updated: usize,
    /// Objets supprimés.
    pub deleted: usize,
    /// Objets déplacés.
    pub relocated: usize,
    /// Avertissements de la bibliothèque.
    pub warnings: Vec<String>,
}

impl MergeReport {
    fn from_log(log: &MergeLog) -> Self {
        let mut report = Self {
            warnings: log.warnings.clone(),
            ..Self::default()
        };
        for event in &log.events {
            match event.event_type {
                MergeEventType::Created => report.created += 1,
                MergeEventType::Deleted => report.deleted += 1,
                MergeEventType::LocationUpdated => report.relocated += 1,
                _ => report.updated += 1,
            }
        }
        report
    }

    /// Vrai si la fusion n'a rien changé.
    pub fn is_empty(&self) -> bool {
        self.created == 0 && self.updated == 0 && self.deleted == 0 && self.relocated == 0
    }

    /// Ajoute le bilan d'une autre fusion.
    pub fn absorb(&mut self, other: MergeReport) {
        self.created += other.created;
        self.updated += other.updated;
        self.deleted += other.deleted;
        self.relocated += other.relocated;
        self.warnings.extend(other.warnings);
    }
}

/// Coffre ouvert en mémoire.
#[derive(Clone)]
pub struct Vault {
    db: Database,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("name", &self.name())
            .field("entries", &self.db.num_entries())
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Crée un coffre vide : KDBX 4.1, AES-256, Argon2id selon `kdf`.
    pub fn create(name: &str, kdf: KdfParams) -> Result<Self> {
        kdf.validate()?;
        let mut config = DatabaseConfig::default();
        config.version = DatabaseVersion::KDB4(1);
        config.outer_cipher_config = OuterCipherConfig::AES256;
        config.inner_cipher_config = InnerCipherConfig::ChaCha20;
        config.compression_config = CompressionConfig::GZip;
        config.kdf_config = kdf.to_config();
        let mut db = Database::with_config(config);
        db.meta.database_name = Some(name.to_owned());
        db.meta.generator = Some("ligrivsstore".to_owned());
        db.meta.history_max_items = Some(10);
        db.root_mut().name = name.to_owned();
        Ok(Self { db })
    }

    /// Ouvre un coffre à partir de son contenu chiffré.
    ///
    /// L'en-tête est contrôlé avant toute dérivation de clé : un fichier dont
    /// les paramètres dépassent `limits` est refusé sans calcul.
    pub fn open(bytes: &[u8], key: &VaultKey, limits: &OpenLimits) -> Result<Self> {
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if size > limits.max_file_bytes {
            return Err(Error::TooLarge {
                size,
                max: limits.max_file_bytes,
            });
        }
        let info = header::inspect(bytes)?;
        limits.check(&info)?;
        if key.is_empty() {
            return Err(Error::InvalidInput(
                "clé vide : une phrase de passe ou un fichier clé est nécessaire".into(),
            ));
        }
        let database_key = key.database_key();
        match catch_unwind(AssertUnwindSafe(|| Database::parse(bytes, database_key))) {
            Ok(Ok(db)) => Ok(Self { db }),
            Ok(Err(error)) => Err(open_error(error)),
            Err(_) => Err(Error::Corrupt(
                "lecture interrompue par la bibliothèque : fichier malformé".into(),
            )),
        }
    }

    /// Sérialise le coffre chiffré, toujours en KDBX 4.1.
    ///
    /// Les paramètres de dérivation sont d'abord ramenés dans notre politique
    /// ([`kdf::normalize`]) ; le chiffrement interne passe en ChaCha20.
    pub fn to_bytes(&mut self, key: &VaultKey) -> Result<Vec<u8>> {
        if key.is_empty() {
            return Err(Error::InvalidInput(
                "clé vide : une phrase de passe ou un fichier clé est nécessaire".into(),
            ));
        }
        let config = &mut self.db.config;
        config.version = DatabaseVersion::KDB4(1);
        config.kdf_config = kdf::normalize(&config.kdf_config);
        config.inner_cipher_config = InnerCipherConfig::ChaCha20;
        if !matches!(
            config.outer_cipher_config,
            OuterCipherConfig::AES256 | OuterCipherConfig::ChaCha20 | OuterCipherConfig::Twofish
        ) {
            config.outer_cipher_config = OuterCipherConfig::AES256;
        }
        let mut out = Vec::new();
        self.db
            .save(&mut out, key.database_key())
            .map_err(|e| Error::Save(e.to_string()))?;
        Ok(out)
    }

    /// Nom du coffre.
    pub fn name(&self) -> Option<&str> {
        self.db.meta.database_name.as_deref()
    }

    /// Identité du coffre : identifiant du groupe racine, commun à toutes les
    /// copies d'un même coffre.
    pub fn identity(&self) -> String {
        self.db.root().id().uuid().to_string()
    }

    /// Version du format en mémoire (par exemple « KDBX4.1 »).
    pub fn format_version(&self) -> String {
        self.db.config.version.to_string()
    }

    /// Paramètres de dérivation actuels.
    pub fn kdf(&self) -> Option<Kdf> {
        kdf::describe(&self.db.config.kdf_config)
    }

    /// Nombre d'entrées, corbeille comprise.
    pub fn entry_count(&self) -> usize {
        self.db.num_entries()
    }

    /// Entrées hors corbeille, triées par titre.
    pub fn entries(&self) -> Vec<EntrySummary> {
        let mut list: Vec<EntrySummary> = self
            .db
            .iter_all_entries()
            .filter(|e| !self.in_recycle_bin(e))
            .map(|e| summary(&e))
            .collect();
        list.sort_by(|a, b| {
            a.title
                .to_lowercase()
                .cmp(&b.title.to_lowercase())
                .then_with(|| a.id.cmp(&b.id))
        });
        list
    }

    /// Entrées dont le titre, l'adresse ou l'identifiant contient `query`
    /// (sans tenir compte de la casse).
    pub fn find(&self, query: &str) -> Vec<EntrySummary> {
        let query = query.to_lowercase();
        self.entries()
            .into_iter()
            .filter(|e| {
                e.title.to_lowercase().contains(&query)
                    || e.url.to_lowercase().contains(&query)
                    || e.username.to_lowercase().contains(&query)
            })
            .collect()
    }

    /// Détail d'une entrée, mot de passe compris.
    pub fn entry(&self, id: &str) -> Result<EntryDetails> {
        let entry_id = parse_id(id)?;
        let entry = self
            .db
            .entry(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.to_owned()))?;
        let base = summary(&entry);
        Ok(EntryDetails {
            id: base.id,
            title: base.title,
            url: base.url,
            username: base.username,
            password: Zeroizing::new(entry.get_password().unwrap_or_default().to_owned()),
            notes: entry.get(fields::NOTES).unwrap_or_default().to_owned(),
            modified: base.modified,
            history_len: entry.history.as_ref().map_or(0, |h| h.get_entries().len()),
        })
    }

    /// Ajoute une entrée à la racine du coffre ; renvoie son identifiant.
    pub fn add_entry(&mut self, input: &EntryInput) -> Result<String> {
        input.validate()?;
        let mut root = self.db.root_mut();
        let mut entry = root.add_entry();
        entry.edit(|e| {
            e.set_unprotected(fields::TITLE, input.title.as_str());
            e.set_unprotected(fields::URL, input.url.as_str());
            e.set_unprotected(fields::USERNAME, input.username.as_str());
            e.set_protected(fields::PASSWORD, input.password.as_str());
            e.set_unprotected(fields::NOTES, input.notes.as_str());
        });
        Ok(entry.id().uuid().to_string())
    }

    /// Modifie une entrée en conservant la version précédente dans son
    /// historique. Renvoie `false` si rien n'a changé.
    pub fn update_entry(&mut self, id: &str, input: &EntryInput) -> Result<bool> {
        input.validate()?;
        let entry_id = parse_id(id)?;
        let history_limit = self.history_limit();
        let mut entry = self
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.to_owned()))?;
        let unchanged = entry.get_title().unwrap_or_default() == input.title
            && entry.get_url().unwrap_or_default() == input.url
            && entry.get_username().unwrap_or_default() == input.username
            && entry.get_password().unwrap_or_default() == input.password.as_str()
            && entry.get(fields::NOTES).unwrap_or_default() == input.notes;
        if unchanged {
            return Ok(false);
        }
        let stamp = next_modification_time(entry.times.last_modification);
        entry.edit_tracking(|e| {
            e.set_unprotected(fields::TITLE, input.title.as_str());
            e.set_unprotected(fields::URL, input.url.as_str());
            e.set_unprotected(fields::USERNAME, input.username.as_str());
            e.set_protected(fields::PASSWORD, input.password.as_str());
            e.set_unprotected(fields::NOTES, input.notes.as_str());
            e.times.last_modification = Some(stamp);
        });
        if let Some(history) = entry.history.as_mut() {
            trim_history(history, history_limit);
        }
        self.db.remove_unused_attachments();
        Ok(true)
    }

    /// Supprime une entrée. La suppression est inscrite dans le coffre, pour
    /// être propagée aux autres terminaux lors de la fusion.
    pub fn delete_entry(&mut self, id: &str) -> Result<()> {
        let entry_id = parse_id(id)?;
        let mut entry = self
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.to_owned()))?;
        entry.track_changes().remove();
        self.db.remove_unused_attachments();
        Ok(())
    }

    /// Fusionne une autre version du même coffre dans celui-ci.
    ///
    /// Les entrées sont rapprochées par identifiant ; pour une entrée modifiée
    /// des deux côtés, la version la plus récente l'emporte et l'autre rejoint
    /// l'historique ; les suppressions sont propagées. En cas d'échec, ce coffre
    /// n'est pas modifié.
    pub fn merge_from(&mut self, other: &Vault) -> Result<MergeReport> {
        if self.db.root().id() != other.db.root().id() {
            return Err(Error::DifferentVaults);
        }
        let mut merged = self.db.clone();
        let log = merged
            .merge(&other.db)
            .map_err(|e| Error::Merge(e.to_string()))?;
        self.db = merged;
        Ok(MergeReport::from_log(&log))
    }

    /// Accès en lecture au coffre de la bibliothèque, pour les tests et les
    /// outils de diagnostic.
    pub fn database(&self) -> &Database {
        &self.db
    }

    fn history_limit(&self) -> usize {
        match self.db.meta.history_max_items {
            Some(n) if n >= 0 => usize::try_from(n).unwrap_or(usize::MAX),
            Some(_) => usize::MAX,
            None => DEFAULT_HISTORY_ITEMS,
        }
    }

    fn in_recycle_bin(&self, entry: &EntryRef<'_>) -> bool {
        let Some(bin) = self.db.meta.recyclebin_uuid else {
            return false;
        };
        // Remontée bornée : un fichier malformé ne doit pas faire boucler.
        let mut current = Some(entry.parent().id());
        for _ in 0..1024 {
            let Some(id) = current else {
                return false;
            };
            if id.uuid() == bin {
                return true;
            }
            current = self.db.group(id).and_then(|g| g.parent().map(|p| p.id()));
        }
        false
    }
}

/// Horodatage d'une nouvelle version : maintenant, ou une seconde après la
/// version précédente si celle-ci date de la même seconde (ou d'un instant
/// postérieur, horloge décalée).
fn next_modification_time(previous: Option<NaiveDateTime>) -> NaiveDateTime {
    let now = Times::now();
    match previous {
        Some(previous) if previous >= now => TimeDelta::try_seconds(1)
            .and_then(|one| previous.checked_add_signed(one))
            .unwrap_or(now),
        _ => now,
    }
}

/// Garde les `limit` versions les plus récentes de l'historique.
fn trim_history(history: &mut History, limit: usize) {
    let versions = history.get_entries();
    if versions.len() <= limit {
        return;
    }
    let kept: Vec<_> = versions.iter().take(limit).cloned().collect();
    let mut trimmed = History::default();
    // L'historique place la version ajoutée en tête : on ajoute de la plus
    // ancienne à la plus récente.
    for version in kept.into_iter().rev() {
        trimmed.add_entry(version);
    }
    *history = trimmed;
}

fn summary(entry: &EntryRef<'_>) -> EntrySummary {
    EntrySummary {
        id: entry.id().uuid().to_string(),
        title: entry.get_title().unwrap_or_default().to_owned(),
        url: entry.get_url().unwrap_or_default().to_owned(),
        username: entry.get_username().unwrap_or_default().to_owned(),
        modified: entry
            .times
            .last_modification
            .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
    }
}

fn parse_id(id: &str) -> Result<EntryId> {
    Uuid::parse_str(id)
        .map(EntryId::from_uuid)
        .map_err(|_| Error::InvalidInput(format!("identifiant d'entrée invalide : {id}")))
}

fn open_error(error: DatabaseOpenError) -> Error {
    match error {
        DatabaseOpenError::Key(DatabaseKeyError::IncorrectKey) => Error::WrongKey,
        DatabaseOpenError::Key(other) => Error::InvalidInput(format!("clé du coffre : {other}")),
        DatabaseOpenError::UnsupportedVersion => Error::Unsupported("version de KDBX".into()),
        other => Error::Corrupt(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast() -> KdfParams {
        KdfParams {
            iterations: crate::kdf::MIN_ITERATIONS,
            ..KdfParams::default()
        }
    }

    fn input(title: &str, password: &str) -> EntryInput {
        EntryInput {
            title: title.into(),
            url: "https://exemple.test".into(),
            username: "hermann".into(),
            password: Zeroizing::new(password.into()),
            notes: String::new(),
        }
    }

    #[test]
    fn rapid_updates_keep_history_timestamps_distinct() {
        let mut vault = Vault::create("essai", fast()).unwrap();
        let id = vault.add_entry(&input("Banque", "v1")).unwrap();
        for i in 2..6 {
            assert!(
                vault
                    .update_entry(&id, &input("Banque", &format!("v{i}")))
                    .unwrap()
            );
        }
        let entry = vault.database().entry(parse_id(&id).unwrap()).unwrap();
        let mut stamps: Vec<_> = entry
            .history
            .as_ref()
            .unwrap()
            .get_entries()
            .iter()
            .map(|h| h.times.last_modification)
            .collect();
        stamps.push(entry.times.last_modification);
        let mut unique = stamps.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            stamps.len(),
            "horodatages en double : {stamps:?}"
        );
    }

    #[test]
    fn unchanged_update_adds_no_history() {
        let mut vault = Vault::create("essai", fast()).unwrap();
        let id = vault.add_entry(&input("Banque", "v1")).unwrap();
        assert!(!vault.update_entry(&id, &input("Banque", "v1")).unwrap());
        assert_eq!(vault.entry(&id).unwrap().history_len, 0);
    }

    #[test]
    fn history_is_trimmed() {
        let mut vault = Vault::create("essai", fast()).unwrap();
        let id = vault.add_entry(&input("Banque", "v0")).unwrap();
        for i in 1..=15 {
            vault
                .update_entry(&id, &input("Banque", &format!("v{i}")))
                .unwrap();
        }
        let details = vault.entry(&id).unwrap();
        assert_eq!(details.history_len, DEFAULT_HISTORY_ITEMS);
        assert_eq!(details.password.as_str(), "v15");
    }

    #[test]
    fn debug_output_hides_secrets() {
        let key = VaultKey::new().with_password("phrase très secrète");
        assert!(!format!("{key:?}").contains("secrète"));
        let entry = input("Banque", "mot-de-passe-secret");
        assert!(!format!("{entry:?}").contains("mot-de-passe-secret"));
    }

    #[test]
    fn title_is_required() {
        let mut vault = Vault::create("essai", fast()).unwrap();
        assert!(matches!(
            vault.add_entry(&input("  ", "x")),
            Err(Error::InvalidInput(_))
        ));
    }
}
