//! Session de l'application : coffre ouvert ou verrouillé.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ligrivsstore_core::generator::{
    PassphrasePolicy, PasswordPolicy, generate_passphrase as generate_phrase,
    generate_password as generate,
};
use ligrivsstore_core::sync::SyncError;
use ligrivsstore_core::{
    EntryInput, Error, KdfParams, LocalVault, OpenLimits, SYNC_ROLE, SyncOptions, VaultKey, keyfile,
};
use zeroize::Zeroizing;

use crate::autopilot::LockReason;
use crate::dto::{
    BackupView, CopyField, CreateVaultRequest, EntryRow, EntryView, Generated, GeneratorOptions,
    InstallRequest, KeyfileChoice, OpenVaultRequest, PassphraseOptions, Preferences, RestoreView,
    SaveEntryRequest, Status, SyncSettingsRequest, SyncSettingsView,
};
use crate::error::AppError;
use crate::monitor::Monitor;
use crate::settings::{self, CLIPBOARD_SECONDS, LOCK_MINUTES, Settings};
use crate::strength::passphrase_strength;
use crate::synchro::{
    DEFAULT_FILE, DEFAULT_SERVER, SYNC_ENTRY_NOTES, SYNC_ENTRY_TITLE, SyncOutcome, SyncTarget,
};

/// Pause imposée après un refus d'identifiants pendant une installation
/// depuis le serveur : cinq refus en rafale font bannir l'adresse 4 heures.
pub const INSTALL_PAUSE: Duration = Duration::from_secs(60);

/// Durée d'ouverture visée à la création d'un coffre (calibrage d'Argon2id).
///
/// Un enregistrement dérive la clé deux fois (écriture, puis relecture de
/// contrôle) : il dure donc environ le double.
pub const CALIBRATION_TARGET: Duration = Duration::from_millis(800);

/// Longueurs admises par le générateur.
const GENERATOR_LENGTHS: std::ops::RangeInclusive<usize> = 8..=128;

/// Session : réglages et, quand il est déverrouillé, le coffre ouvert.
pub struct Session {
    settings_path: PathBuf,
    settings: Settings,
    vault: Option<LocalVault>,
    /// Le coffre en mémoire contient des modifications non enregistrées.
    unsaved: bool,
    /// Durée d'ouverture visée pour les coffres créés.
    calibration: Duration,
    /// État observable par l'interface pendant que la session est occupée.
    monitor: Arc<Monitor>,
    /// Autorité de certification des bancs d'essai (jamais en service).
    root_ca_pem: Option<Vec<u8>>,
    /// Dernier refus d'identifiants pendant une installation depuis le serveur.
    install_refused_at: Option<Instant>,
}

impl Session {
    /// Charge les réglages enregistrés dans `config_dir`. Ne bloque jamais :
    /// des réglages illisibles sont remplacés par des réglages vides.
    pub fn load(config_dir: &Path) -> Self {
        let settings_path = config_dir.join(settings::FILE_NAME);
        Self {
            settings: Settings::load(&settings_path),
            settings_path,
            vault: None,
            unsaved: false,
            calibration: CALIBRATION_TARGET,
            monitor: Arc::new(Monitor::default()),
            root_ca_pem: None,
            install_refused_at: None,
        }
    }

    /// État observable, à partager avec la coquille et l'interface.
    pub fn monitor(&self) -> Arc<Monitor> {
        Arc::clone(&self.monitor)
    }

    /// Ne reconnaît que cette autorité de certification pour le serveur :
    /// bancs d'essai seulement. Par défaut, seules les autorités publiques.
    pub fn set_root_ca(&mut self, pem: Option<Vec<u8>>) {
        self.root_ca_pem = pem;
    }

    /// Change la durée d'ouverture visée pour les coffres créés ensuite
    /// (essais, diagnostic). Par défaut : [`CALIBRATION_TARGET`].
    pub fn set_calibration_target(&mut self, target: Duration) {
        self.calibration = target;
    }

    /// État courant.
    pub fn status(&self) -> Status {
        let display = |p: &Option<PathBuf>| p.as_ref().map(|p| p.display().to_string());
        match &self.vault {
            Some(local) => Status {
                unlocked: true,
                vault_path: Some(local.path().display().to_string()),
                keyfile_path: display(&self.settings.last_keyfile),
                vault_name: local.vault().name().map(str::to_owned),
                entry_count: local
                    .vault()
                    .entries()
                    .iter()
                    .filter(|e| e.role.is_none())
                    .count(),
                unsaved: self.unsaved,
            },
            None => Status {
                unlocked: false,
                vault_path: display(&self.settings.last_vault),
                keyfile_path: display(&self.settings.last_keyfile),
                vault_name: None,
                entry_count: 0,
                unsaved: false,
            },
        }
    }

    /// Crée un coffre, l'ouvre et le retient comme dernier coffre.
    ///
    /// La phrase de passe doit être assez robuste ; un coffre ou un fichier clé
    /// existant n'est jamais remplacé.
    pub fn create_vault(&mut self, request: CreateVaultRequest) -> Result<Status, AppError> {
        let passphrase = Zeroizing::new(request.passphrase);
        let strength = passphrase_strength(&passphrase);
        if !strength.acceptable {
            return Err(AppError::new(
                "phrase_trop_faible",
                "phrase de passe trop faible : au moins 12 caractères et une robustesse « bonne »",
            ));
        }
        let path = required_path(&request.path, "emplacement du coffre")?;
        if path.exists() {
            return Err(AppError::new(
                "existe_deja",
                format!("le fichier existe déjà : {}", path.display()),
            ));
        }
        let name = match request.name.trim() {
            "" => "Coffre",
            name => name,
        };
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(ligrivsstore_core::Error::from)?;
        }

        let (keyfile_path, generated) = match request.keyfile {
            KeyfileChoice::None => (None, false),
            KeyfileChoice::Existing { path } => (Some(required_path(&path, "fichier clé")?), false),
            KeyfileChoice::Generate { path } => {
                let path = required_path(&path, "fichier clé")?;
                if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                    std::fs::create_dir_all(parent).map_err(ligrivsstore_core::Error::from)?;
                }
                keyfile::create(&path)?;
                (Some(path), true)
            }
        };
        let calibration = self.calibration;
        let created = (|| {
            let key = vault_key(&passphrase, keyfile_path.as_deref())?;
            let kdf = KdfParams::calibrate(calibration)?;
            Ok::<_, AppError>(LocalVault::create(&path, name, key, kdf)?)
        })();
        let local = match created {
            Ok(local) => local,
            Err(error) => {
                // Un fichier clé créé pour un coffre qui n'existe pas ne sert à rien.
                if generated && let Some(keyfile) = &keyfile_path {
                    let _ = std::fs::remove_file(keyfile);
                }
                return Err(error);
            }
        };
        self.vault = Some(local);
        self.unsaved = false;
        self.remember(path, keyfile_path);
        self.monitor.unlocked(false, None);
        Ok(self.status())
    }

    /// Ouvre un coffre et le retient comme dernier coffre.
    pub fn open_vault(&mut self, request: OpenVaultRequest) -> Result<Status, AppError> {
        let passphrase = Zeroizing::new(request.passphrase);
        let path = required_path(&request.path, "emplacement du coffre")?;
        let keyfile_path = request
            .keyfile_path
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(PathBuf::from);
        let key = vault_key(&passphrase, keyfile_path.as_deref())?;
        let local = LocalVault::open(&path, key, OpenLimits::default())?;
        self.vault = Some(local);
        self.unsaved = false;
        self.remember(path, keyfile_path);
        self.announce_unlocked();
        Ok(self.status())
    }

    /// Verrouille : le coffre et sa clé sont retirés de la mémoire.
    pub fn lock(&mut self, reason: LockReason) -> Status {
        self.vault = None;
        self.unsaved = false;
        self.monitor.locked(reason, self.settings.lock_minutes);
        self.status()
    }

    /// Vrai si un coffre est ouvert.
    pub fn is_unlocked(&self) -> bool {
        self.vault.is_some()
    }

    /// Oublie le dernier coffre (pour en ouvrir ou en créer un autre). Le
    /// coffre doit être verrouillé ; aucun fichier n'est supprimé.
    pub fn forget_vault(&mut self) -> Result<Status, AppError> {
        if self.vault.is_some() {
            return Err(AppError::new(
                "deverrouille",
                "verrouillez d'abord le coffre ouvert",
            ));
        }
        self.settings.last_vault = None;
        self.settings.last_keyfile = None;
        self.settings.save(&self.settings_path)?;
        Ok(self.status())
    }

    /// Réglages de l'application.
    pub fn preferences(&self) -> Preferences {
        Preferences {
            lock_minutes: self.settings.lock_minutes,
            clipboard_seconds: self.settings.clipboard_seconds,
        }
    }

    /// Change les réglages de l'application.
    pub fn set_preferences(&mut self, preferences: Preferences) -> Result<Preferences, AppError> {
        if !LOCK_MINUTES.contains(&preferences.lock_minutes) {
            return Err(AppError::new(
                "parametre_invalide",
                "délai de verrouillage : de 1 à 60 minutes",
            ));
        }
        if !CLIPBOARD_SECONDS.contains(&preferences.clipboard_seconds) {
            return Err(AppError::new(
                "parametre_invalide",
                "effacement du presse-papiers : de 10 à 120 secondes",
            ));
        }
        self.settings.lock_minutes = preferences.lock_minutes;
        self.settings.clipboard_seconds = preferences.clipboard_seconds;
        self.settings.save(&self.settings_path)?;
        Ok(self.preferences())
    }

    /// Entrées dont le titre, l'identifiant ou l'adresse contient `query`
    /// (sans tenir compte de la casse), triées par titre.
    pub fn list_entries(&self, query: &str) -> Result<Vec<EntryRow>, AppError> {
        let vault = self.local()?.vault();
        let query = query.trim().to_lowercase();
        let matches = |text: &str| text.to_lowercase().contains(&query);
        let mut rows: Vec<EntryRow> = vault
            .entries()
            .into_iter()
            .filter(|e| e.role.is_none())
            .filter(|e| {
                query.is_empty() || matches(&e.title) || matches(&e.username) || matches(&e.url)
            })
            .map(|e| EntryRow {
                id: e.id,
                title: e.title,
                username: e.username,
                url: e.url,
            })
            .collect();
        rows.sort_by(|a, b| {
            a.title
                .to_lowercase()
                .cmp(&b.title.to_lowercase())
                .then_with(|| a.username.cmp(&b.username))
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(rows)
    }

    /// Fiche d'une entrée, sans son mot de passe.
    pub fn entry(&self, id: &str) -> Result<EntryView, AppError> {
        self.ordinary(id)?;
        let details = self.local()?.vault().entry(id)?;
        Ok(EntryView {
            id: details.id.clone(),
            title: details.title.clone(),
            url: details.url.clone(),
            username: details.username.clone(),
            notes: details.notes.clone(),
            has_password: !details.password.is_empty(),
            modified: details.modified.clone(),
            history_len: details.history_len,
        })
    }

    /// Mot de passe d'une entrée, à la demande explicite de l'utilisateur.
    pub fn reveal_password(&self, id: &str) -> Result<Zeroizing<String>, AppError> {
        self.ordinary(id)?;
        Ok(self.local()?.vault().entry(id)?.password.clone())
    }

    /// Identifiant ou mot de passe d'une entrée, à copier dans le
    /// presse-papiers.
    pub fn secret_for_copy(
        &self,
        id: &str,
        field: CopyField,
    ) -> Result<Zeroizing<String>, AppError> {
        self.ordinary(id)?;
        let details = self.local()?.vault().entry(id)?;
        let value = match field {
            CopyField::Username => Zeroizing::new(details.username.clone()),
            CopyField::Password => details.password.clone(),
        };
        if value.is_empty() {
            return Err(AppError::new(
                "parametre_invalide",
                "rien à copier : le champ est vide",
            ));
        }
        Ok(value)
    }

    /// Crée ou modifie une entrée, puis enregistre le coffre. Renvoie
    /// l'identifiant de l'entrée.
    ///
    /// Si l'enregistrement échoue, la modification reste en mémoire et l'état
    /// le signale (`unsaved`) : [`Session::retry_save`] la réessaie.
    pub fn save_entry(&mut self, request: SaveEntryRequest) -> Result<String, AppError> {
        if let Some(id) = &request.id {
            self.ordinary(id)?;
        }
        let local = self.local_mut()?;
        let password = match (request.password, &request.id) {
            (Some(password), _) => Zeroizing::new(password),
            (None, Some(id)) => local.vault().entry(id)?.password.clone(),
            (None, None) => Zeroizing::new(String::new()),
        };
        let input = EntryInput {
            title: request.title.trim().to_owned(),
            url: request.url.trim().to_owned(),
            username: request.username.trim().to_owned(),
            password,
            notes: request.notes,
        };
        let (id, changed) = match request.id {
            Some(id) => {
                let changed = local.vault_mut().update_entry(&id, &input)?;
                (id, changed)
            }
            None => (local.vault_mut().add_entry(&input)?, true),
        };
        if changed {
            self.unsaved = true;
            self.retry_save()?;
        }
        Ok(id)
    }

    /// Supprime une entrée, puis enregistre le coffre.
    pub fn delete_entry(&mut self, id: &str) -> Result<(), AppError> {
        self.ordinary(id)?;
        self.local_mut()?.vault_mut().delete_entry(id)?;
        self.unsaved = true;
        self.retry_save()
    }

    /// Enregistre le coffre ouvert (écriture atomique, relue, avec
    /// sauvegarde de la version précédente).
    pub fn retry_save(&mut self) -> Result<(), AppError> {
        self.local_mut()?.save()?;
        self.unsaved = false;
        Ok(())
    }

    /// Réglage de la synchronisation enregistré dans le coffre ouvert.
    pub fn sync_settings(&self) -> Result<SyncSettingsView, AppError> {
        let vault = self.local()?.vault();
        let Some(id) = vault.role_entry(SYNC_ROLE) else {
            return Ok(SyncSettingsView {
                configured: false,
                server: DEFAULT_SERVER.to_owned(),
                account: String::new(),
                file: DEFAULT_FILE.to_owned(),
                has_password: false,
            });
        };
        let details = vault.entry(&id)?;
        let target = SyncTarget::from_url(&details.url);
        Ok(SyncSettingsView {
            configured: true,
            server: target
                .as_ref()
                .map_or_else(|| DEFAULT_SERVER.to_owned(), |t| t.server.clone()),
            account: details.username.clone(),
            file: target.map_or_else(|| DEFAULT_FILE.to_owned(), |t| t.file),
            has_password: !details.password.is_empty(),
        })
    }

    /// Règle la synchronisation : adresse, compte et mot de passe du serveur,
    /// rangés dans l'entrée réservée du coffre. Si les identifiants changent,
    /// la suspension qui suit un refus est levée. Renvoie le réglage et
    /// `true` si quelque chose a changé.
    pub fn configure_sync(
        &mut self,
        request: SyncSettingsRequest,
    ) -> Result<(SyncSettingsView, bool), AppError> {
        let target = SyncTarget::new(&request.server, &request.account, &request.file)?;
        let typed = request
            .password
            .filter(|p| !p.is_empty())
            .map(Zeroizing::new);
        let root_ca = self.root_ca_pem.clone();
        let local = self.local_mut()?;
        let existing = local.vault().role_entry(SYNC_ROLE);
        let password = match (typed, &existing) {
            (Some(password), _) => password,
            (None, Some(id)) => local.vault().entry(id)?.password.clone(),
            (None, None) => {
                return Err(AppError::new(
                    "parametre_invalide",
                    "saisissez le mot de passe du serveur",
                ));
            }
        };
        // Adresse, compte et règles du serveur vérifiés avant d'enregistrer.
        target.transport(&password, root_ca.as_deref())?;
        let input = sync_entry(&target, password);
        let changed = match existing {
            Some(id) => local.vault_mut().update_entry(&id, &input)?,
            None => {
                local.vault_mut().add_role_entry(&input, SYNC_ROLE)?;
                true
            }
        };
        if changed {
            self.unsaved = true;
            self.retry_save()?;
            self.local_mut()?.accept_new_credentials()?;
        }
        self.monitor.set_configured(true);
        Ok((self.sync_settings()?, changed))
    }

    /// Synchronise avec le serveur, si la synchronisation est réglée. La
    /// session reste occupée pendant l'échange (30 secondes au plus par
    /// requête) ; l'interface suit l'état par le [`Monitor`].
    pub fn sync_now(&mut self) -> SyncOutcome {
        if self.vault.is_none() {
            return SyncOutcome::Locked;
        }
        let (target, password) = match self.sync_credentials() {
            Ok(Some(credentials)) => credentials,
            Ok(None) => {
                self.monitor.set_configured(false);
                return SyncOutcome::NotConfigured;
            }
            Err(error) => {
                let outcome = SyncOutcome::Failed(error.message);
                self.monitor.sync_finished(&outcome);
                return outcome;
            }
        };
        self.monitor.sync_started();
        let outcome = match (
            target.transport(&password, self.root_ca_pem.as_deref()),
            self.vault.as_mut(),
        ) {
            (Err(error), _) => SyncOutcome::Failed(error.message),
            (Ok(_), None) => SyncOutcome::Locked,
            (Ok(transport), Some(local)) => {
                SyncOutcome::from_result(local.sync(&transport, &SyncOptions::default()))
            }
        };
        // Un envoi ou une fusion a écrit le coffre en mémoire sur le disque.
        if let SyncOutcome::Done {
            uploaded, merged, ..
        } = outcome
            && (uploaded || merged > 0)
        {
            self.unsaved = false;
        }
        self.monitor.sync_finished(&outcome);
        outcome
    }

    /// Installe sur ce PC le coffre présent sur le serveur, l'ouvre, et y
    /// range les identifiants du serveur saisis.
    pub fn install_from_server(&mut self, request: InstallRequest) -> Result<Status, AppError> {
        if let Some(refused) = self.install_refused_at {
            let elapsed = refused.elapsed();
            if elapsed < INSTALL_PAUSE {
                return Err(AppError::new(
                    "patienter",
                    format!(
                        "patientez encore {} s avant un nouvel essai : le serveur bloque votre adresse pendant 4 heures après cinq refus en rafale",
                        (INSTALL_PAUSE - elapsed).as_secs().max(1)
                    ),
                ));
            }
        }
        let passphrase = Zeroizing::new(request.passphrase);
        let server_password = Zeroizing::new(request.server_password);
        let target = SyncTarget::new(&request.server, &request.account, &request.file)?;
        let path = required_path(&request.path, "emplacement du coffre")?;
        if path.exists() {
            return Err(AppError::new(
                "existe_deja",
                format!("le fichier existe déjà : {}", path.display()),
            ));
        }
        let keyfile_path = request
            .keyfile_path
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(PathBuf::from);
        let key = vault_key(&passphrase, keyfile_path.as_deref())?;
        let transport = target.transport(&server_password, self.root_ca_pem.as_deref())?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(Error::from)?;
        }
        let local = match LocalVault::clone_from_remote(
            &path,
            key,
            OpenLimits::default(),
            &transport,
        ) {
            Ok(local) => local,
            Err(Error::Sync(SyncError::Unauthorized)) => {
                self.install_refused_at = Some(Instant::now());
                return Err(AppError::new(
                    "identifiants_refuses",
                    "compte ou mot de passe du serveur refusé. Vérifiez-les avant un nouvel essai : après cinq refus en rafale, le serveur bloque votre adresse pendant 4 heures",
                ));
            }
            Err(Error::Sync(SyncError::RemoteWrongKey)) => {
                return Err(AppError::new(
                    "cle_incorrecte",
                    "phrase de passe ou fichier clé incorrect pour le coffre du serveur",
                ));
            }
            Err(Error::Sync(SyncError::RemoteMissing)) => {
                return Err(AppError::new(
                    "coffre_absent",
                    "aucun coffre à cette adresse sur le serveur : vérifiez le compte et le nom du coffre",
                ));
            }
            Err(error) => return Err(error.into()),
        };
        self.install_refused_at = None;
        self.vault = Some(local);
        self.unsaved = false;
        self.remember(path, keyfile_path);
        // Identifiants du serveur saisis sur ce PC : dans l'entrée réservée.
        let input = sync_entry(&target, server_password);
        let local = self.local_mut()?;
        let changed = match local.vault().role_entry(SYNC_ROLE) {
            Some(id) => local.vault_mut().update_entry(&id, &input)?,
            None => {
                local.vault_mut().add_role_entry(&input, SYNC_ROLE)?;
                true
            }
        };
        if changed {
            self.unsaved = true;
            // Un échec reste signalé (`unsaved`) : le coffre est installé.
            let _ = self.retry_save();
        }
        self.announce_unlocked();
        Ok(self.status())
    }

    /// Sauvegardes locales du coffre ouvert, de la plus récente à la plus
    /// ancienne.
    pub fn backups(&self) -> Result<Vec<BackupView>, AppError> {
        Ok(self
            .local()?
            .backups()?
            .into_iter()
            .filter_map(|b| {
                let id = b.path.file_name()?.to_string_lossy().into_owned();
                Some(BackupView {
                    id,
                    replaced: b.replaced_utc,
                    size: b.size,
                })
            })
            .collect())
    }

    /// Rétablit les entrées d'une sauvegarde (la version remplacée de chaque
    /// entrée rejoint son historique), puis enregistre le coffre.
    pub fn restore_backup(&mut self, id: &str) -> Result<RestoreView, AppError> {
        let local = self.local_mut()?;
        let backup = local.open_backup(id)?;
        let report = local.vault_mut().restore_entries_from(&backup)?;
        if report.restored + report.recreated > 0 {
            self.unsaved = true;
            self.monitor.bump_revision();
            self.retry_save()?;
        }
        Ok(RestoreView {
            restored: report.restored,
            recreated: report.recreated,
            unchanged: report.unchanged,
            skipped: report.skipped,
        })
    }

    fn sync_credentials(&self) -> Result<Option<(SyncTarget, Zeroizing<String>)>, AppError> {
        let vault = self.local()?.vault();
        let Some(id) = vault.role_entry(SYNC_ROLE) else {
            return Ok(None);
        };
        let details = vault.entry(&id)?;
        let stored = SyncTarget::from_url(&details.url).ok_or_else(|| {
            AppError::new(
                "parametre_invalide",
                "adresse du serveur illisible dans le coffre : réglez de nouveau la synchronisation",
            )
        })?;
        let target = SyncTarget::new(&stored.server, &details.username, &stored.file)?;
        Ok(Some((target, details.password.clone())))
    }

    /// Annonce l'ouverture du coffre, avec l'état de sa synchronisation.
    fn announce_unlocked(&self) {
        let Some(local) = self.vault.as_ref() else {
            return;
        };
        let configured = local.vault().role_entry(SYNC_ROLE).is_some();
        self.monitor
            .unlocked(configured, local.sync_state().last_sync_utc.clone());
    }

    /// Refuse les entrées réservées à l'application (identifiants du
    /// serveur) aux commandes ordinaires de l'interface.
    fn ordinary(&self, id: &str) -> Result<(), AppError> {
        let reserved = self
            .local()?
            .vault()
            .entries()
            .into_iter()
            .any(|e| e.id == id && e.role.is_some());
        if reserved {
            return Err(AppError::new(
                "entree_reservee",
                "entrée réservée à l'application : modifiez-la depuis l'écran Synchronisation",
            ));
        }
        Ok(())
    }

    fn local(&self) -> Result<&LocalVault, AppError> {
        self.vault.as_ref().ok_or_else(AppError::locked)
    }

    fn local_mut(&mut self) -> Result<&mut LocalVault, AppError> {
        self.vault.as_mut().ok_or_else(AppError::locked)
    }

    /// Retient le coffre et son fichier clé ; un échec d'écriture des réglages
    /// n'empêche pas d'utiliser le coffre.
    fn remember(&mut self, vault: PathBuf, keyfile: Option<PathBuf>) {
        self.settings.last_vault = Some(vault);
        self.settings.last_keyfile = keyfile;
        let _ = self.settings.save(&self.settings_path);
    }
}

/// Entrée réservée qui garde les identifiants du serveur.
fn sync_entry(target: &SyncTarget, password: Zeroizing<String>) -> EntryInput {
    EntryInput {
        title: SYNC_ENTRY_TITLE.to_owned(),
        url: target.url(),
        username: target.account.clone(),
        password,
        notes: SYNC_ENTRY_NOTES.to_owned(),
    }
}

/// Génère une phrase de passe (liste de mots de l'EFF).
pub fn generate_passphrase(options: &PassphraseOptions) -> Result<Generated, AppError> {
    let mut chars = options.separator.chars();
    let (Some(separator), None) = (chars.next(), chars.next()) else {
        return Err(AppError::new(
            "parametre_invalide",
            "séparateur : un seul caractère",
        ));
    };
    let policy = PassphrasePolicy {
        words: options.words,
        separator,
        capitalize: options.capitalize,
        digit: options.digit,
    };
    let phrase = generate_phrase(&policy)?;
    Ok(Generated {
        password: phrase.as_str().to_owned(),
        entropy_bits: policy.entropy_bits(),
    })
}

/// Génère un mot de passe.
pub fn generate_password(options: &GeneratorOptions) -> Result<Generated, AppError> {
    if !GENERATOR_LENGTHS.contains(&options.length) {
        return Err(AppError::new(
            "parametre_invalide",
            "longueur du mot de passe : de 8 à 128 caractères",
        ));
    }
    let policy = PasswordPolicy {
        length: options.length,
        lowercase: options.lowercase,
        uppercase: options.uppercase,
        digits: options.digits,
        symbols: options.symbols,
        exclude_ambiguous: options.exclude_ambiguous,
    };
    let password = generate(&policy)?;
    Ok(Generated {
        password: password.as_str().to_owned(),
        entropy_bits: policy.entropy_bits(),
    })
}

fn required_path(text: &str, what: &str) -> Result<PathBuf, AppError> {
    match text.trim() {
        "" => Err(AppError::new(
            "parametre_invalide",
            format!("{what} : emplacement manquant"),
        )),
        text => Ok(PathBuf::from(text)),
    }
}

/// Clé du coffre : phrase de passe (si elle n'est pas vide) et fichier clé.
fn vault_key(passphrase: &str, keyfile_path: Option<&Path>) -> Result<VaultKey, AppError> {
    let mut key = VaultKey::new();
    if !passphrase.is_empty() {
        key = key.with_password(passphrase);
    }
    if let Some(path) = keyfile_path {
        let bytes = keyfile::read(path)?;
        key = key.with_keyfile(&bytes)?;
    }
    if key.is_empty() {
        return Err(AppError::new(
            "parametre_invalide",
            "saisissez la phrase de passe du coffre",
        ));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSPHRASE: &str = "corail-prisme-vélo-tonnerre-anis";

    struct Fixture {
        dir: tempfile::TempDir,
        session: Session,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let mut session = Session::load(&dir.path().join("config"));
            // Coffres rapides à ouvrir : ces essais en créent beaucoup.
            session.set_calibration_target(Duration::from_millis(20));
            Self { dir, session }
        }

        fn path(&self, name: &str) -> String {
            self.dir.path().join(name).display().to_string()
        }

        fn create(&mut self, keyfile: KeyfileChoice) -> Status {
            let path = self.path("coffres/coffre.kdbx");
            self.session
                .create_vault(CreateVaultRequest {
                    path,
                    name: "Coffre de test".into(),
                    passphrase: PASSPHRASE.into(),
                    keyfile,
                })
                .unwrap()
        }

        fn add(&mut self, title: &str, password: &str) -> String {
            self.session
                .save_entry(SaveEntryRequest {
                    id: None,
                    title: title.into(),
                    url: format!("https://{}.exemple", title.to_lowercase()),
                    username: "hermann".into(),
                    password: Some(password.into()),
                    notes: String::new(),
                })
                .unwrap()
        }
    }

    #[test]
    fn create_lock_and_reopen_with_a_generated_key_file() {
        let mut f = Fixture::new();
        let keyfile = f.path("cles/coffre.keyx");
        let status = f.create(KeyfileChoice::Generate {
            path: keyfile.clone(),
        });
        assert!(status.unlocked);
        assert_eq!(status.vault_name.as_deref(), Some("Coffre de test"));
        assert_eq!(status.keyfile_path.as_deref(), Some(keyfile.as_str()));
        f.add("Banque", "secret-banque");

        let status = f.session.lock(LockReason::Manual);
        assert!(!status.unlocked);
        assert!(matches!(f.session.list_entries(""), Err(e) if e.code == "verrouille"));
        // Les réglages retiennent le coffre et son fichier clé.
        let reloaded = Session::load(&f.dir.path().join("config"));
        assert_eq!(
            reloaded.status().keyfile_path.as_deref(),
            Some(keyfile.as_str())
        );

        let status = f
            .session
            .open_vault(OpenVaultRequest {
                path: f.path("coffres/coffre.kdbx"),
                passphrase: PASSPHRASE.into(),
                keyfile_path: Some(keyfile),
            })
            .unwrap();
        assert!(status.unlocked);
        assert_eq!(status.entry_count, 1);
    }

    #[test]
    fn wrong_key_and_missing_key_file_are_reported() {
        let mut f = Fixture::new();
        let keyfile = f.path("coffre.keyx");
        f.create(KeyfileChoice::Generate {
            path: keyfile.clone(),
        });
        f.session.lock(LockReason::Manual);
        let vault = f.path("coffres/coffre.kdbx");
        let absent = f.path("absente.keyx");
        let mut open = |passphrase: &str, keyfile: Option<String>| {
            f.session.open_vault(OpenVaultRequest {
                path: vault.clone(),
                passphrase: passphrase.into(),
                keyfile_path: keyfile,
            })
        };
        let error = open("mauvaise phrase de passe", Some(keyfile.clone())).unwrap_err();
        assert_eq!(error.code, "cle_incorrecte");
        let error = open(PASSPHRASE, None).unwrap_err();
        assert_eq!(error.code, "cle_incorrecte");
        let error = open(PASSPHRASE, Some(absent)).unwrap_err();
        assert_eq!(error.code, "fichier_cle_introuvable");
        assert!(error.message.contains("absente.keyx"));
        assert!(!f.session.status().unlocked);
    }

    #[test]
    fn creation_refuses_a_weak_passphrase_and_an_existing_file() {
        let mut f = Fixture::new();
        let request = |path: String, passphrase: &str| CreateVaultRequest {
            path,
            name: String::new(),
            passphrase: passphrase.into(),
            keyfile: KeyfileChoice::None,
        };
        let error = f
            .session
            .create_vault(request(f.path("a.kdbx"), "azerty123"))
            .unwrap_err();
        assert_eq!(error.code, "phrase_trop_faible");
        assert!(!f.dir.path().join("a.kdbx").exists());

        std::fs::write(f.dir.path().join("b.kdbx"), b"existant").unwrap();
        let error = f
            .session
            .create_vault(request(f.path("b.kdbx"), PASSPHRASE))
            .unwrap_err();
        assert_eq!(error.code, "existe_deja");
        assert_eq!(
            std::fs::read(f.dir.path().join("b.kdbx")).unwrap(),
            b"existant"
        );
    }

    #[test]
    fn a_generated_key_file_is_removed_when_creation_fails() {
        let mut f = Fixture::new();
        // Le fichier clé est créé, puis le coffre échoue : nom de fichier trop
        // long pour le système de fichiers.
        let keyfile = f.path("cle.keyx");
        let too_long = f.path(&format!("{}.kdbx", "x".repeat(300)));
        let outcome = f.session.create_vault(CreateVaultRequest {
            path: too_long,
            name: String::new(),
            passphrase: PASSPHRASE.into(),
            keyfile: KeyfileChoice::Generate {
                path: keyfile.clone(),
            },
        });
        assert!(outcome.is_err());
        assert!(!Path::new(&keyfile).exists());
    }

    #[test]
    fn entries_are_listed_searched_viewed_and_revealed() {
        let mut f = Fixture::new();
        f.create(KeyfileChoice::None);
        let banque = f.add("Banque", "secret-banque");
        f.add("messagerie", "secret-messagerie");
        f.add("Assurance", "secret-assurance");

        let titles: Vec<String> = f
            .session
            .list_entries("")
            .unwrap()
            .into_iter()
            .map(|r| r.title)
            .collect();
        assert_eq!(titles, ["Assurance", "Banque", "messagerie"]);
        let found = f.session.list_entries("  BANQUE ").unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(
            f.session.list_entries("messagerie.exemple").unwrap().len(),
            1
        );
        assert!(f.session.list_entries("introuvable").unwrap().is_empty());

        let view = f.session.entry(&banque).unwrap();
        assert!(view.has_password);
        assert_eq!(view.username, "hermann");
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("secret-banque"), "{json}");
        assert_eq!(
            f.session.reveal_password(&banque).unwrap().as_str(),
            "secret-banque"
        );
    }

    #[test]
    fn editing_keeps_the_password_unless_a_new_one_is_given() {
        let mut f = Fixture::new();
        f.create(KeyfileChoice::None);
        let id = f.add("Banque", "secret-banque");
        let edit = |password: Option<&str>, username: &str| SaveEntryRequest {
            id: Some(id.clone()),
            title: "Banque".into(),
            url: "https://banque.exemple".into(),
            username: username.into(),
            password: password.map(str::to_owned),
            notes: "note".into(),
        };
        f.session.save_entry(edit(None, "hermann.k")).unwrap();
        assert_eq!(
            f.session.reveal_password(&id).unwrap().as_str(),
            "secret-banque"
        );
        assert_eq!(f.session.entry(&id).unwrap().history_len, 1);

        f.session
            .save_entry(edit(Some("nouveau-secret"), "hermann.k"))
            .unwrap();
        assert_eq!(
            f.session.reveal_password(&id).unwrap().as_str(),
            "nouveau-secret"
        );
        assert_eq!(f.session.entry(&id).unwrap().history_len, 2);

        // Les modifications sont sur le disque : le coffre rouvert les montre.
        f.session.lock(LockReason::Manual);
        f.session
            .open_vault(OpenVaultRequest {
                path: f.path("coffres/coffre.kdbx"),
                passphrase: PASSPHRASE.into(),
                keyfile_path: None,
            })
            .unwrap();
        let view = f.session.entry(&id).unwrap();
        assert_eq!(view.username, "hermann.k");
        assert_eq!(view.notes, "note");
        assert!(!f.session.status().unsaved);
    }

    #[test]
    fn deleting_an_entry_is_saved() {
        let mut f = Fixture::new();
        f.create(KeyfileChoice::None);
        let id = f.add("Banque", "secret-banque");
        f.session.delete_entry(&id).unwrap();
        f.session.lock(LockReason::Manual);
        let status = f
            .session
            .open_vault(OpenVaultRequest {
                path: f.path("coffres/coffre.kdbx"),
                passphrase: PASSPHRASE.into(),
                keyfile_path: None,
            })
            .unwrap();
        assert_eq!(status.entry_count, 0);
        assert!(matches!(f.session.entry(&id), Err(e) if e.code == "entree_introuvable"));
    }

    #[test]
    fn an_entry_needs_a_title() {
        let mut f = Fixture::new();
        f.create(KeyfileChoice::None);
        let error = f
            .session
            .save_entry(SaveEntryRequest {
                id: None,
                title: "   ".into(),
                url: String::new(),
                username: String::new(),
                password: None,
                notes: String::new(),
            })
            .unwrap_err();
        assert_eq!(error.code, "parametre_invalide");
    }

    #[test]
    fn forgetting_the_last_vault_needs_it_locked() {
        let mut f = Fixture::new();
        f.create(KeyfileChoice::None);
        assert_eq!(f.session.forget_vault().unwrap_err().code, "deverrouille");
        f.session.lock(LockReason::Manual);
        let status = f.session.forget_vault().unwrap();
        assert!(status.vault_path.is_none());
        let reloaded = Session::load(&f.dir.path().join("config"));
        assert!(reloaded.status().vault_path.is_none());
    }

    #[test]
    fn the_generator_respects_its_options() {
        let generated = generate_password(&GeneratorOptions {
            length: 24,
            lowercase: true,
            uppercase: false,
            digits: true,
            symbols: false,
            exclude_ambiguous: true,
        })
        .unwrap();
        assert_eq!(generated.password.chars().count(), 24);
        assert!(
            generated
                .password
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
        assert!(generated.entropy_bits > 100.0);
        let too_short = GeneratorOptions {
            length: 4,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        };
        assert_eq!(
            generate_password(&too_short).unwrap_err().code,
            "parametre_invalide"
        );
    }

    /// Faux serveur local : répond `status` à chaque requête, et compte les
    /// requêtes reçues.
    struct FakeServer {
        address: String,
        requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl FakeServer {
        fn start(status: &'static str) -> Self {
            use std::io::{BufRead, BufReader, Write};
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = format!("http://{}", listener.local_addr().unwrap());
            let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counter = std::sync::Arc::clone(&requests);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
                        if line == "\r\n" {
                            break;
                        }
                        line.clear();
                    }
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                }
            });
            Self { address, requests }
        }

        fn requests(&self) -> usize {
            self.requests.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    fn sync_request(server: &str, password: Option<&str>) -> SyncSettingsRequest {
        SyncSettingsRequest {
            server: server.into(),
            account: "hermann".into(),
            file: "coffre.kdbx".into(),
            password: password.map(str::to_owned),
        }
    }

    #[test]
    fn the_sync_settings_live_in_a_hidden_reserved_entry() {
        let mut f = Fixture::new();
        f.create(KeyfileChoice::None);
        f.add("Banque", "secret-banque");
        assert!(!f.session.sync_settings().unwrap().configured);
        assert_eq!(f.session.sync_now(), SyncOutcome::NotConfigured);

        // Le mot de passe du serveur est exigé la première fois.
        let error = f
            .session
            .configure_sync(sync_request("https://coffre.ligrivs.com", None))
            .unwrap_err();
        assert_eq!(error.code, "parametre_invalide");
        // Une adresse en http:// vers un autre ordinateur est refusée.
        let error = f
            .session
            .configure_sync(sync_request(
                "http://coffre.ligrivs.com",
                Some("mdp-serveur"),
            ))
            .unwrap_err();
        assert!(error.message.contains("https"), "{}", error.message);

        let (view, changed) = f
            .session
            .configure_sync(sync_request(
                "https://coffre.ligrivs.com/",
                Some("mdp-serveur"),
            ))
            .unwrap();
        assert!(changed);
        assert!(view.configured && view.has_password);
        assert_eq!(view.server, "https://coffre.ligrivs.com");
        assert_eq!(view.account, "hermann");
        assert_eq!(view.file, "coffre.kdbx");
        // Même réglage, sans nouveau mot de passe : rien ne change.
        let (_, changed) = f
            .session
            .configure_sync(sync_request("https://coffre.ligrivs.com", None))
            .unwrap();
        assert!(!changed);

        // L'entrée réservée n'apparaît ni dans la liste ni dans le compte, et
        // les commandes ordinaires la refusent.
        let rows = f.session.list_entries("").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(f.session.status().entry_count, 1);
        let reserved = f
            .session
            .local()
            .unwrap()
            .vault()
            .role_entry(SYNC_ROLE)
            .unwrap();
        for code in [
            f.session.entry(&reserved).unwrap_err().code,
            f.session.reveal_password(&reserved).unwrap_err().code,
            f.session
                .secret_for_copy(&reserved, CopyField::Password)
                .unwrap_err()
                .code,
            f.session.delete_entry(&reserved).unwrap_err().code,
        ] {
            assert_eq!(code, "entree_reservee");
        }

        // Le réglage est dans le fichier du coffre : il survit au verrouillage.
        f.session.lock(LockReason::Manual);
        f.session
            .open_vault(OpenVaultRequest {
                path: f.path("coffres/coffre.kdbx"),
                passphrase: PASSPHRASE.into(),
                keyfile_path: None,
            })
            .unwrap();
        assert!(f.session.sync_settings().unwrap().configured);
        assert!(f.session.monitor().activity().sync.configured);
    }

    #[test]
    fn an_unreachable_server_means_offline_and_a_refusal_suspends() {
        let mut f = Fixture::new();
        f.create(KeyfileChoice::None);
        // Port fermé sur la machine locale : connexion refusée aussitôt.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://{}", closed.local_addr().unwrap());
        drop(closed);
        f.session
            .configure_sync(sync_request(&address, Some("mdp")))
            .unwrap();
        assert!(matches!(f.session.sync_now(), SyncOutcome::Offline(_)));
        assert_eq!(f.session.monitor().activity().sync.state, "hors_ligne");

        let server = FakeServer::start("401 Unauthorized");
        f.session
            .configure_sync(sync_request(&server.address, Some("mauvais")))
            .unwrap();
        assert!(matches!(f.session.sync_now(), SyncOutcome::Suspended(_)));
        assert_eq!(server.requests(), 1);
        // Suspendue : plus aucune requête, même après redémarrage du coffre.
        assert!(matches!(f.session.sync_now(), SyncOutcome::Suspended(_)));
        f.session.lock(LockReason::Manual);
        f.session
            .open_vault(OpenVaultRequest {
                path: f.path("coffres/coffre.kdbx"),
                passphrase: PASSPHRASE.into(),
                keyfile_path: None,
            })
            .unwrap();
        assert!(matches!(f.session.sync_now(), SyncOutcome::Suspended(_)));
        assert_eq!(server.requests(), 1);
        assert_eq!(f.session.monitor().activity().sync.state, "suspendue");
        // Nouvelle saisie : la suspension est levée, une requête repart.
        f.session
            .configure_sync(sync_request(&server.address, Some("nouveau")))
            .unwrap();
        assert!(matches!(f.session.sync_now(), SyncOutcome::Suspended(_)));
        assert_eq!(server.requests(), 2);
    }

    #[test]
    fn installing_after_a_refusal_waits_a_minute_without_contacting_the_server() {
        let mut f = Fixture::new();
        let server = FakeServer::start("401 Unauthorized");
        let request = |path: String| InstallRequest {
            server: server.address.clone(),
            account: "hermann".into(),
            file: "coffre.kdbx".into(),
            server_password: "mauvais".into(),
            path,
            passphrase: PASSPHRASE.into(),
            keyfile_path: None,
        };
        let error = f
            .session
            .install_from_server(request(f.path("pc2/coffre.kdbx")))
            .unwrap_err();
        assert_eq!(error.code, "identifiants_refuses");
        assert!(error.message.contains("4 heures"));
        let error = f
            .session
            .install_from_server(request(f.path("pc2/coffre.kdbx")))
            .unwrap_err();
        assert_eq!(error.code, "patienter");
        assert_eq!(server.requests(), 1);
        assert!(!f.dir.path().join("pc2/coffre.kdbx").exists());

        let missing = FakeServer::start("404 Not Found");
        let mut other = Fixture::new();
        let error = other
            .session
            .install_from_server(InstallRequest {
                server: missing.address.clone(),
                ..request(other.path("pc2/coffre.kdbx"))
            })
            .unwrap_err();
        assert_eq!(error.code, "coffre_absent");
    }

    #[test]
    fn backups_are_listed_and_restored_from_the_session() {
        let mut f = Fixture::new();
        f.create(KeyfileChoice::None);
        let id = f.add("Banque", "v1");
        f.session
            .save_entry(SaveEntryRequest {
                id: Some(id.clone()),
                title: "Banque".into(),
                url: String::new(),
                username: "hermann".into(),
                password: Some("v2".into()),
                notes: String::new(),
            })
            .unwrap();
        let backups = f.session.backups().unwrap();
        assert!(backups.len() >= 2, "{backups:?}");
        assert!(backups.iter().all(|b| b.replaced.is_some() && b.size > 0));
        let revision = f.session.monitor().activity().revision;
        // La plus récente : l'entrée avec le mot de passe v1.
        let report = f.session.restore_backup(&backups[0].id).unwrap();
        assert_eq!(report.restored, 1);
        assert_eq!(f.session.reveal_password(&id).unwrap().as_str(), "v1");
        assert!(f.session.monitor().activity().revision > revision);
        assert!(!f.session.status().unsaved);
        assert_eq!(
            f.session.restore_backup("../coffre.kdbx").unwrap_err().code,
            "parametre_invalide"
        );
    }

    #[test]
    fn copy_preferences_and_passphrases() {
        let mut f = Fixture::new();
        f.create(KeyfileChoice::None);
        let id = f.add("Banque", "secret-banque");
        assert_eq!(
            f.session
                .secret_for_copy(&id, CopyField::Password)
                .unwrap()
                .as_str(),
            "secret-banque"
        );
        assert_eq!(
            f.session
                .secret_for_copy(&id, CopyField::Username)
                .unwrap()
                .as_str(),
            "hermann"
        );

        assert_eq!(f.session.preferences().lock_minutes, 5);
        assert_eq!(f.session.preferences().clipboard_seconds, 30);
        let saved = f
            .session
            .set_preferences(Preferences {
                lock_minutes: 15,
                clipboard_seconds: 60,
            })
            .unwrap();
        assert_eq!(saved.lock_minutes, 15);
        for wrong in [(0, 30), (61, 30), (5, 9), (5, 121)] {
            assert!(
                f.session
                    .set_preferences(Preferences {
                        lock_minutes: wrong.0,
                        clipboard_seconds: wrong.1,
                    })
                    .is_err()
            );
        }
        // Oublier le coffre garde les délais.
        f.session.lock(LockReason::Manual);
        f.session.forget_vault().unwrap();
        let reloaded = Session::load(&f.dir.path().join("config"));
        assert_eq!(reloaded.preferences().lock_minutes, 15);

        let phrase = generate_passphrase(&PassphraseOptions {
            words: 5,
            separator: " ".into(),
            capitalize: true,
            digit: false,
        })
        .unwrap();
        assert_eq!(phrase.password.split(' ').count(), 5);
        assert!(phrase.entropy_bits > 64.0);
        assert!(
            generate_passphrase(&PassphraseOptions {
                words: 5,
                separator: "--".into(),
                capitalize: false,
                digit: false,
            })
            .is_err()
        );
    }
}
