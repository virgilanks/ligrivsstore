//! Session de l'application : coffre ouvert ou verrouillé.

use std::path::{Path, PathBuf};
use std::time::Duration;

use ligrivsstore_core::generator::{PasswordPolicy, generate_password as generate};
use ligrivsstore_core::{EntryInput, KdfParams, LocalVault, OpenLimits, VaultKey, keyfile};
use zeroize::Zeroizing;

use crate::dto::{
    CreateVaultRequest, EntryRow, EntryView, Generated, GeneratorOptions, KeyfileChoice,
    OpenVaultRequest, SaveEntryRequest, Status,
};
use crate::error::AppError;
use crate::settings::{self, Settings};
use crate::strength::passphrase_strength;

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
        }
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
                entry_count: local.vault().entry_count(),
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
        Ok(self.status())
    }

    /// Verrouille : le coffre et sa clé sont retirés de la mémoire.
    pub fn lock(&mut self) -> Status {
        self.vault = None;
        self.unsaved = false;
        self.status()
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
        self.settings = Settings::default();
        self.settings.save(&self.settings_path)?;
        Ok(self.status())
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
        Ok(self.local()?.vault().entry(id)?.password.clone())
    }

    /// Crée ou modifie une entrée, puis enregistre le coffre. Renvoie
    /// l'identifiant de l'entrée.
    ///
    /// Si l'enregistrement échoue, la modification reste en mémoire et l'état
    /// le signale (`unsaved`) : [`Session::retry_save`] la réessaie.
    pub fn save_entry(&mut self, request: SaveEntryRequest) -> Result<String, AppError> {
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

        let status = f.session.lock();
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
        f.session.lock();
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
        f.session.lock();
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
        f.session.lock();
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
        f.session.lock();
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
}
