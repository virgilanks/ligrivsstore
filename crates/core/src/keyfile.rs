//! Fichiers clés.
//!
//! Le noyau crée les fichiers clés au format XML 2.0 de KeePass, celui que
//! génèrent KeePass 2 et KeePassXC : 32 octets aléatoires écrits en
//! hexadécimal, suivis d'une somme de contrôle (les 4 premiers octets de leur
//! empreinte SHA-256). KeePassXC, KeePassDX et KeePassium les lisent sans
//! avertissement.
//!
//! Tout autre fichier reste accepté comme fichier clé, selon les règles de
//! KeePass : 32 octets bruts, 64 caractères hexadécimaux, sinon empreinte
//! SHA-256 du fichier entier.

use std::path::Path;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::storage::write_new_file;

/// Taille de la clé d'un fichier clé généré, en octets.
pub const KEY_SIZE: usize = 32;

/// Génère le contenu d'un nouveau fichier clé, au format XML 2.0 de KeePass.
pub fn generate() -> Result<Zeroizing<String>> {
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    getrandom::fill(key.as_mut_slice()).map_err(|_| Error::Random)?;
    Ok(xml_v2(key.as_slice()))
}

/// Crée un nouveau fichier clé à `path`, lisible par son seul propriétaire.
///
/// Un fichier existant n'est jamais remplacé : perdre un fichier clé, c'est
/// perdre l'accès au coffre.
pub fn create(path: &Path) -> Result<()> {
    let content = generate()?;
    match write_new_file(path, content.as_bytes()) {
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(Error::AlreadyExists(path.display().to_string()))
        }
        outcome => outcome,
    }
}

/// Lit un fichier clé. Son absence est signalée avec son emplacement.
pub fn read(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Zeroizing::new(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(Error::KeyFileNotFound(path.display().to_string()))
        }
        Err(error) => Err(error.into()),
    }
}

/// Vérifie la somme de contrôle d'un fichier clé XML 2.0, comme KeePassXC.
///
/// Un fichier modifié ou endommagé est ainsi signalé comme tel, au lieu d'une
/// « clé incorrecte ». Les autres formats n'ont pas de somme de contrôle et
/// sont acceptés tels quels.
pub fn verify_checksum(bytes: &[u8]) -> Result<()> {
    match parse_xml_v2(bytes) {
        Some(file) if checksum(&file.key) != file.checksum => Err(Error::KeyFileCorrupt),
        _ => Ok(()),
    }
}

/// Mise en forme identique à celle de KeePassXC : indentation de 4 espaces,
/// hexadécimal en majuscules, groupes de 8 caractères, 4 groupes par ligne.
fn xml_v2(key: &[u8]) -> Zeroizing<String> {
    // Capacité suffisante pour éviter toute réallocation : une copie de la clé
    // resterait sinon dans la mémoire libérée.
    let mut out = Zeroizing::new(String::with_capacity(512));
    out.push_str(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <KeyFile>\n    <Meta>\n        <Version>2.0</Version>\n    </Meta>\n    <Key>\n        <Data Hash=\"",
    );
    out.push_str(&hex::encode_upper(checksum(key)));
    out.push_str("\">");
    for (index, group) in key.chunks(4).enumerate() {
        out.push_str(if index % 4 == 0 {
            "\n            "
        } else {
            " "
        });
        out.push_str(&Zeroizing::new(hex::encode_upper(group)));
    }
    out.push_str("\n        </Data>\n    </Key>\n</KeyFile>\n");
    out
}

/// Somme de contrôle du format XML 2.0 : les 4 premiers octets de l'empreinte
/// SHA-256 de la clé.
fn checksum(key: &[u8]) -> [u8; 4] {
    let digest = Sha256::digest(key);
    let mut out = [0u8; 4];
    for (slot, byte) in out.iter_mut().zip(digest.iter()) {
        *slot = *byte;
    }
    out
}

struct XmlV2 {
    checksum: [u8; 4],
    key: Zeroizing<Vec<u8>>,
}

/// Reconnaît un fichier clé XML 2.0 portant une somme de contrôle.
///
/// En cas de doute (autre format, autre version, structure inattendue),
/// renvoie `None` : la vérification est alors sautée, et la lecture du fichier
/// suit les règles habituelles de KeePass.
fn parse_xml_v2(bytes: &[u8]) -> Option<XmlV2> {
    let text = std::str::from_utf8(bytes).ok()?;
    let text = text.trim_start_matches('\u{feff}').trim_start();
    if !text.starts_with('<') {
        return None;
    }
    if between(text, "<Version>", "</Version>")?.trim() != "2.0" {
        return None;
    }
    let data = text.get(text.find("<Data")?..)?;
    let tag_end = data.find('>')?;
    let tag = data.get(..tag_end)?;
    let checksum_hex = between(tag, "Hash=\"", "\"")?.trim();
    let content = data.get(tag_end.checked_add(1)?..data.find("</Data>")?)?;
    let hex_key = Zeroizing::new(
        content
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>(),
    );
    let key = Zeroizing::new(hex::decode(hex_key.as_bytes()).ok()?);
    let checksum = <[u8; 4]>::try_from(hex::decode(checksum_hex).ok()?.as_slice()).ok()?;
    Some(XmlV2 { checksum, key })
}

/// Texte compris entre `start` et la première occurrence suivante de `end`.
fn between<'a>(text: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let from = text.find(start)?.checked_add(start.len())?;
    let rest = text.get(from..)?;
    rest.get(..rest.find(end)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KdfParams, LocalVault, OpenLimits, VaultKey};

    #[test]
    fn a_generated_key_file_follows_the_keepassxc_layout() {
        let content = generate().unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 12, "{}", content.as_str());
        assert_eq!(lines[0], "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        assert_eq!(lines[3], "        <Version>2.0</Version>");
        assert!(lines[6].starts_with("        <Data Hash=\"") && lines[6].ends_with("\">"));
        for line in &lines[7..9] {
            let groups: Vec<&str> = line.trim_start().split(' ').collect();
            assert!(line.starts_with("            "));
            assert_eq!(groups.len(), 4);
            for group in groups {
                assert_eq!(group.len(), 8);
                assert!(
                    group
                        .chars()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())
                );
            }
        }
        assert_eq!(lines[11], "</KeyFile>");
    }

    #[test]
    fn a_generated_key_file_carries_a_valid_checksum() {
        let content = generate().unwrap();
        let file = parse_xml_v2(content.as_bytes()).unwrap();
        assert_eq!(file.key.len(), KEY_SIZE);
        assert_eq!(checksum(&file.key), file.checksum);
        verify_checksum(content.as_bytes()).unwrap();
    }

    #[test]
    fn two_generated_key_files_differ() {
        assert_ne!(generate().unwrap(), generate().unwrap());
    }

    #[test]
    fn a_damaged_key_file_is_reported_as_such() {
        let content = generate().unwrap();
        let data_line = content.lines().nth(7).unwrap().to_owned();
        let first = data_line.trim_start().chars().next().unwrap();
        let replacement = if first == '0' { '1' } else { '0' };
        let damaged_line = data_line.replacen(first, &replacement.to_string(), 1);
        let damaged = content.replacen(&data_line, &damaged_line, 1);
        assert!(matches!(
            verify_checksum(damaged.as_bytes()),
            Err(Error::KeyFileCorrupt)
        ));
        assert!(matches!(
            VaultKey::new().with_keyfile(damaged.as_bytes()),
            Err(Error::KeyFileCorrupt)
        ));
    }

    #[test]
    fn other_key_file_formats_have_no_checksum_to_verify() {
        let mut random = vec![0u8; 64];
        getrandom::fill(&mut random).unwrap();
        verify_checksum(&random).unwrap();
        verify_checksum(&[7u8; 32]).unwrap();
        verify_checksum(b"<?xml version=\"1.0\"?><KeyFile><Meta><Version>1.00</Version></Meta><Key><Data>AAAA</Data></Key></KeyFile>").unwrap();
        // Version 2.0 sans somme de contrôle : rien à vérifier.
        verify_checksum(b"<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data>00112233</Data></Key></KeyFile>").unwrap();
    }

    /// Les règles de KeePass donnent la même clé pour le fichier XML 2.0 et
    /// pour le fichier brut de 32 octets qui contient les mêmes octets : la
    /// clé écrite en hexadécimal est donc bien celle qui protège le coffre.
    #[test]
    fn the_xml_key_file_protects_the_vault_with_its_own_32_bytes() {
        let content = generate().unwrap();
        let raw = parse_xml_v2(content.as_bytes()).unwrap().key;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("coffre.kdbx");
        let xml_key = VaultKey::new()
            .with_password("phrase de test")
            .with_keyfile(content.as_bytes())
            .unwrap();
        let kdf = KdfParams {
            iterations: 4,
            ..KdfParams::default()
        };
        LocalVault::create(&path, "Coffre", xml_key, kdf).unwrap();
        let raw_key = VaultKey::new()
            .with_password("phrase de test")
            .with_keyfile(&raw)
            .unwrap();
        LocalVault::open(&path, raw_key, OpenLimits::default()).unwrap();
    }

    #[test]
    fn create_never_replaces_an_existing_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cle.keyx");
        create(&path).unwrap();
        let first = std::fs::read(&path).unwrap();
        assert!(matches!(create(&path), Err(Error::AlreadyExists(_))));
        assert_eq!(std::fs::read(&path).unwrap(), first);
        verify_checksum(&first).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_created_key_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cle.keyx");
        create(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_missing_key_file_is_named_in_the_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absente.keyx");
        let error = read(&path).unwrap_err();
        assert!(matches!(error, Error::KeyFileNotFound(_)));
        assert!(error.to_string().contains("absente.keyx"), "{error}");
    }
}
