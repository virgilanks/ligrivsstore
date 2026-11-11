//! Stockage local d'un coffre : écriture atomique, relecture de contrôle,
//! sauvegardes tournantes.
//!
//! Un enregistrement ne remplace jamais le fichier en place :
//! 1. le contenu est écrit dans un fichier temporaire du même dossier, puis
//!    forcé sur le disque ;
//! 2. ce fichier est relu et vérifié (le coffre doit se rouvrir avec la clé) ;
//! 3. la version en place est copiée dans le dossier des sauvegardes ;
//! 4. le fichier temporaire remplace l'ancien par renommage (opération
//!    atomique), puis le dossier est forcé sur le disque.
//!
//! Une coupure à n'importe quelle étape laisse soit l'ancienne version, soit
//! la nouvelle, jamais un fichier partiel. La preuve de concept a montré le
//! risque inverse : un fichier vide envoyé au serveur après un enregistrement
//! raté.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::Utc;

use crate::error::{Error, Result};

/// Une sauvegarde locale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupInfo {
    /// Chemin du fichier.
    pub path: PathBuf,
    /// Taille, en octets.
    pub size: u64,
}

/// Emplacement d'un coffre sur le terminal.
#[derive(Debug, Clone)]
pub struct LocalStore {
    path: PathBuf,
    keep_backups: usize,
}

impl LocalStore {
    /// Coffre situé à `path`, avec `keep_backups` sauvegardes conservées
    /// (dans le dossier `<nom du fichier>.sauvegardes` voisin).
    pub fn new(path: impl Into<PathBuf>, keep_backups: usize) -> Self {
        Self {
            path: path.into(),
            keep_backups,
        }
    }

    /// Chemin du coffre.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Vrai si le fichier existe.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Dossier des sauvegardes.
    pub fn backups_dir(&self) -> PathBuf {
        self.sibling(".sauvegardes")
    }

    /// Fichier voisin du coffre portant le même nom suivi de `suffix`.
    pub fn sibling(&self, suffix: &str) -> PathBuf {
        let mut name = self.file_name();
        name.push_str(suffix);
        self.path.with_file_name(name)
    }

    /// Lit le contenu chiffré du coffre.
    pub fn read(&self) -> Result<Vec<u8>> {
        Ok(fs::read(&self.path)?)
    }

    /// Enregistre `bytes` de façon atomique, après les avoir relus et soumis à
    /// `verify` (qui doit, par exemple, rouvrir le coffre avec la clé).
    pub fn write_verified<F>(&self, bytes: &[u8], verify: F) -> Result<()>
    where
        F: FnOnce(&[u8]) -> Result<()>,
    {
        if bytes.is_empty() {
            return Err(Error::Save("contenu vide : enregistrement refusé".into()));
        }
        let directory = self.directory();
        fs::create_dir_all(&directory)?;
        let temporary = directory.join(format!(".{}.{}.tmp", self.file_name(), random_suffix()?));
        let outcome = (|| {
            write_new_file(&temporary, bytes)?;
            let readback = fs::read(&temporary)?;
            if readback != bytes {
                return Err(Error::Save("la relecture diffère de l'écriture".into()));
            }
            verify(&readback)?;
            self.backup_current()?;
            fs::rename(&temporary, &self.path)?;
            sync_directory(&directory)?;
            Ok(())
        })();
        if outcome.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        outcome
    }

    /// Sauvegardes, de la plus récente à la plus ancienne.
    pub fn backups(&self) -> Result<Vec<BackupInfo>> {
        let directory = self.backups_dir();
        if !directory.exists() {
            return Ok(Vec::new());
        }
        let prefix = format!("{}.", self.stem());
        let mut list = Vec::new();
        for item in fs::read_dir(&directory)? {
            let item = item?;
            let name = item.file_name().to_string_lossy().into_owned();
            if name.starts_with(&prefix) && name.ends_with(".kdbx") && item.file_type()?.is_file() {
                list.push(BackupInfo {
                    path: item.path(),
                    size: item.metadata()?.len(),
                });
            }
        }
        // Les noms portent l'horodatage UTC : l'ordre alphabétique est l'ordre
        // chronologique.
        list.sort_by(|a, b| b.path.cmp(&a.path));
        Ok(list)
    }

    fn backup_current(&self) -> Result<()> {
        if self.keep_backups == 0 || !self.path.exists() {
            return Ok(());
        }
        let current = fs::read(&self.path)?;
        if let Some(newest) = self.backups()?.first()
            && fs::read(&newest.path)? == current
        {
            return Ok(());
        }
        let directory = self.backups_dir();
        create_private_dir(&directory)?;
        // Nom : <coffre>.<horodatage UTC>.<numéro d'ordre>.kdbx ; l'ordre
        // alphabétique reste l'ordre chronologique, même pour deux sauvegardes
        // de la même microseconde.
        let stamp = Utc::now().format("%Y%m%dT%H%M%S%.6fZ");
        let mut sequence = 0u32;
        let target = loop {
            let candidate = directory.join(format!("{}.{stamp}.{sequence:03}.kdbx", self.stem()));
            if !candidate.exists() {
                break candidate;
            }
            sequence += 1;
        };
        write_new_file(&target, &current)?;
        for old in self.backups()?.into_iter().skip(self.keep_backups) {
            fs::remove_file(old.path)?;
        }
        Ok(())
    }

    fn directory(&self) -> PathBuf {
        match self.path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => PathBuf::from("."),
        }
    }

    fn file_name(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "coffre.kdbx".to_owned())
    }

    fn stem(&self) -> String {
        self.path
            .file_stem()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "coffre".to_owned())
    }
}

/// Écrit un nouveau fichier (échec s'il existe), lisible par son seul
/// propriétaire, puis le force sur le disque.
pub(crate) fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Remplace `path` de façon atomique par `bytes` (fichier temporaire, puis
/// renommage).
pub(crate) fn replace_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temporary = directory.join(format!(".{name}.{}.tmp", random_suffix()?));
    let outcome = write_new_file(&temporary, bytes)
        .and_then(|()| fs::rename(&temporary, path).map_err(Error::from))
        .and_then(|()| sync_directory(&directory));
    if outcome.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    outcome
}

fn create_private_dir(path: &Path) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

fn sync_directory(directory: &Path) -> Result<()> {
    // Sous Windows, un dossier ne s'ouvre pas comme un fichier ; le renommage
    // y est déjà journalisé par le système de fichiers (NTFS).
    #[cfg(unix)]
    {
        fs::File::open(directory)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
    }
    Ok(())
}

fn random_suffix() -> Result<String> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(|_| Error::Random)?;
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(dir: &Path, keep: usize) -> LocalStore {
        LocalStore::new(dir.join("coffre.kdbx"), keep)
    }

    fn accept(_: &[u8]) -> Result<()> {
        Ok(())
    }

    #[test]
    fn failed_verification_keeps_previous_version_and_leaves_no_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path(), 3);
        store.write_verified(b"version 1", accept).unwrap();
        let refused = store.write_verified(b"version 2", |_| Err(Error::Save("refus".into())));
        assert!(refused.is_err());
        assert_eq!(store.read().unwrap(), b"version 1");
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn empty_content_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(store(dir.path(), 3).write_verified(b"", accept).is_err());
    }

    #[test]
    fn backups_rotate() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path(), 3);
        for i in 0..6 {
            store
                .write_verified(format!("version {i}").as_bytes(), accept)
                .unwrap();
        }
        let backups = store.backups().unwrap();
        assert_eq!(backups.len(), 3);
        assert_eq!(fs::read(&backups[0].path).unwrap(), b"version 4");
        assert_eq!(fs::read(&backups[2].path).unwrap(), b"version 2");
        assert_eq!(store.read().unwrap(), b"version 5");
    }

    #[test]
    fn identical_content_is_not_backed_up_twice() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path(), 5);
        store.write_verified(b"a", accept).unwrap();
        store.write_verified(b"b", accept).unwrap();
        store.write_verified(b"b", accept).unwrap();
        store.write_verified(b"b", accept).unwrap();
        store.write_verified(b"b", accept).unwrap();
        // « a », puis une seule copie de « b » malgré trois remplacements.
        let backups = store.backups().unwrap();
        assert_eq!(backups.len(), 2);
        assert_eq!(fs::read(&backups[0].path).unwrap(), b"b");
        assert_eq!(fs::read(&backups[1].path).unwrap(), b"a");
    }

    #[cfg(unix)]
    #[test]
    fn files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path(), 2);
        store.write_verified(b"a", accept).unwrap();
        store.write_verified(b"b", accept).unwrap();
        let mode = fs::metadata(store.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let backup = &store.backups().unwrap()[0];
        assert_eq!(
            fs::metadata(&backup.path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(store.backups_dir())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}
