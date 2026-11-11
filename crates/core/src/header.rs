//! Lecture de l'en-tête d'un coffre KDBX, sans la clé.
//!
//! La bibliothèque KDBX applique les paramètres de dérivation inscrits dans le
//! fichier **avant** de pouvoir vérifier la clé. Un serveur ou un intermédiaire
//! compromis pourrait donc déposer un fichier qui épuise la mémoire (Argon2 avec
//! plusieurs gibioctets), le processeur (des milliards d'itérations) ou les fils
//! d'exécution du terminal (un fil par voie d'Argon2), voire qui fait échouer la
//! lecture de façon brutale. Ce module relit l'en-tête de façon stricte et compare
//! ces paramètres à des plafonds ([`OpenLimits`]) avant toute ouverture.
//!
//! La lecture est volontairement plus stricte que celle de la bibliothèque : clés
//! en double, types ou longueurs inattendus sont refusés, pour qu'aucun fichier ne
//! puisse être lu d'une façon par ce module et d'une autre par la bibliothèque.

use crate::error::{Error, Result};

const SIGNATURE_1: u32 = 0x9AA2_D903;
const SIGNATURE_2_KDBX: u32 = 0xB54B_FB67;
const SIGNATURE_2_KDB: u32 = 0xB54B_FB65;
const SIGNATURE_2_KDBX_PRE: u32 = 0xB54B_FB66;

const CIPHER_AES256: [u8; 16] = hex_uuid(0x31C1_F2E6_BF71_4350_BE58_0521_6AFC_5AFF);
const CIPHER_CHACHA20: [u8; 16] = hex_uuid(0xD603_8A2B_8B6F_4CB5_A524_339A_31DB_B59A);
const CIPHER_TWOFISH: [u8; 16] = hex_uuid(0xAD68_F29F_576F_4BB9_A36A_D47A_F965_346C);

const KDF_AES_KDBX3: [u8; 16] = hex_uuid(0xC9D9_F39A_628A_4460_BF74_0D08_C18A_4FEA);
const KDF_AES_KDBX4: [u8; 16] = hex_uuid(0x7C02_BB82_79A7_4AC0_927D_114A_0064_8238);
const KDF_ARGON2D: [u8; 16] = hex_uuid(0xEF63_6DDF_8C29_444B_91F7_A9A4_03E3_0A0C);
const KDF_ARGON2ID: [u8; 16] = hex_uuid(0x9E29_8B19_56DB_4773_B23D_FC3E_C6F0_A1E6);

/// Champs d'en-tête utiles (identifiants du format KDBX).
const FIELD_END: u8 = 0;
const FIELD_CIPHER: u8 = 2;
const FIELD_TRANSFORM_ROUNDS: u8 = 6;
const FIELD_KDF_PARAMETERS: u8 = 11;

/// Types de valeurs du dictionnaire de paramètres (KDBX 4).
const VD_END: u8 = 0x00;
const VD_U32: u8 = 0x04;
const VD_U64: u8 = 0x05;
const VD_BOOL: u8 = 0x08;
const VD_I32: u8 = 0x0C;
const VD_I64: u8 = 0x0D;
const VD_STRING: u8 = 0x18;
const VD_BYTES: u8 = 0x42;

const MAX_HEADER_FIELDS: usize = 64;
const MAX_DICTIONARY_ITEMS: usize = 64;

const fn hex_uuid(value: u128) -> [u8; 16] {
    value.to_be_bytes()
}

/// Algorithme de chiffrement du fichier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Cipher {
    /// AES-256 (mode CBC).
    Aes256,
    /// ChaCha20.
    ChaCha20,
    /// Twofish.
    Twofish,
    /// Algorithme inconnu de ce module (la bibliothèque le refusera).
    Unknown,
}

/// Variante d'Argon2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argon2Variant {
    /// Argon2d (choix par défaut de KeePassXC).
    Argon2d,
    /// Argon2id (notre choix).
    Argon2id,
}

/// Fonction de dérivation de clé inscrite dans un coffre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Kdf {
    /// AES-KDF : ancien mécanisme, sans résistance à l'attaque par matériel dédié.
    Aes {
        /// Nombre de tours.
        rounds: u64,
    },
    /// Argon2d ou Argon2id.
    Argon2 {
        /// Variante.
        variant: Argon2Variant,
        /// Mémoire, en octets.
        memory_bytes: u64,
        /// Nombre d'itérations (passes).
        iterations: u64,
        /// Nombre de voies (parallélisme).
        parallelism: u32,
        /// Version de l'algorithme (0x13 pour la version 1.3).
        version: u32,
    },
}

impl std::fmt::Display for Kdf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Kdf::Aes { rounds } => write!(f, "AES-KDF, {rounds} tours"),
            Kdf::Argon2 {
                variant,
                memory_bytes,
                iterations,
                parallelism,
                ..
            } => {
                let name = match variant {
                    Argon2Variant::Argon2d => "Argon2d",
                    Argon2Variant::Argon2id => "Argon2id",
                };
                write!(
                    f,
                    "{name}, {} Mio, {iterations} itérations, {parallelism} voies",
                    memory_bytes / (1024 * 1024)
                )
            }
        }
    }
}

/// Informations lues dans l'en-tête, sans la clé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderInfo {
    /// Version majeure du format (3 ou 4).
    pub major: u16,
    /// Version mineure du format.
    pub minor: u16,
    /// Chiffrement du fichier.
    pub cipher: Cipher,
    /// Dérivation de la clé.
    pub kdf: Kdf,
}

/// Plafonds appliqués avant d'ouvrir un coffre.
///
/// Les valeurs par défaut acceptent les coffres réels (KeePassXC propose
/// jusqu'à quelques centaines de Mio) tout en écartant les valeurs aberrantes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenLimits {
    /// Taille maximale du fichier, en octets.
    pub max_file_bytes: u64,
    /// Mémoire maximale d'Argon2, en octets.
    pub max_argon2_memory_bytes: u64,
    /// Nombre maximal d'itérations d'Argon2.
    pub max_argon2_iterations: u64,
    /// Parallélisme maximal d'Argon2 (un fil d'exécution par voie).
    pub max_argon2_parallelism: u32,
    /// Nombre maximal de tours d'AES-KDF.
    pub max_aes_rounds: u64,
}

impl Default for OpenLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: 64 * 1024 * 1024,
            max_argon2_memory_bytes: 1024 * 1024 * 1024,
            max_argon2_iterations: crate::kdf::MAX_ITERATIONS,
            max_argon2_parallelism: 16,
            max_aes_rounds: 100_000_000,
        }
    }
}

impl OpenLimits {
    /// Plafonds pour l'extension AutoFill d'iOS, qui ne dispose que d'environ
    /// 120 Mo de mémoire.
    pub fn ios_autofill() -> Self {
        Self {
            max_argon2_memory_bytes: 64 * 1024 * 1024,
            ..Self::default()
        }
    }

    /// Vérifie les paramètres de dérivation lus dans l'en-tête.
    pub fn check(&self, info: &HeaderInfo) -> Result<()> {
        match info.kdf {
            Kdf::Aes { rounds } => {
                if rounds == 0 || rounds > self.max_aes_rounds {
                    return Err(Error::KdfRejected(format!(
                        "AES-KDF avec {rounds} tours (accepté : 1 à {})",
                        self.max_aes_rounds
                    )));
                }
            }
            Kdf::Argon2 {
                memory_bytes,
                iterations,
                parallelism,
                ..
            } => {
                if memory_bytes > self.max_argon2_memory_bytes {
                    return Err(Error::KdfRejected(format!(
                        "Argon2 demande {} Mio de mémoire (maximum {} Mio)",
                        memory_bytes / (1024 * 1024),
                        self.max_argon2_memory_bytes / (1024 * 1024)
                    )));
                }
                if iterations == 0 || iterations > self.max_argon2_iterations {
                    return Err(Error::KdfRejected(format!(
                        "Argon2 avec {iterations} itérations (accepté : 1 à {})",
                        self.max_argon2_iterations
                    )));
                }
                if parallelism == 0 || parallelism > self.max_argon2_parallelism {
                    return Err(Error::KdfRejected(format!(
                        "Argon2 avec {parallelism} voies (accepté : 1 à {})",
                        self.max_argon2_parallelism
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Lit l'en-tête d'un coffre KDBX 3.1 ou 4.x, sans la clé.
pub fn inspect(data: &[u8]) -> Result<HeaderInfo> {
    let mut r = Reader::new(data);
    let signature_1 = r.u32()?;
    let signature_2 = r.u32()?;
    if signature_1 != SIGNATURE_1 {
        return Err(Error::Corrupt(
            "ce fichier n'est pas un coffre KeePass".into(),
        ));
    }
    match signature_2 {
        SIGNATURE_2_KDBX => {}
        SIGNATURE_2_KDB => return Err(Error::Unsupported("KeePass 1.x (KDB)".into())),
        SIGNATURE_2_KDBX_PRE => return Err(Error::Unsupported("préversion de KDBX 2".into())),
        _ => return Err(Error::Corrupt("signature KeePass inconnue".into())),
    }
    let minor = r.u16()?;
    let major = r.u16()?;
    if major != 3 && major != 4 {
        return Err(Error::Unsupported(format!("KDBX {major}.{minor}")));
    }

    let mut seen = [false; 256];
    let mut cipher = None;
    let mut kdf = None;
    let mut aes_rounds = None;
    for _ in 0..MAX_HEADER_FIELDS {
        let id = r.u8()?;
        let length = if major >= 4 {
            to_usize(r.u32()?)?
        } else {
            usize::from(r.u16()?)
        };
        let value = r.take(length)?;
        if let Some(already) = seen.get_mut(usize::from(id)) {
            if *already {
                return Err(Error::Corrupt(format!("champ d'en-tête {id} en double")));
            }
            *already = true;
        }
        match id {
            FIELD_END => {
                let cipher = cipher.ok_or_else(|| corrupt("algorithme de chiffrement absent"))?;
                let kdf = if major >= 4 {
                    kdf.ok_or_else(|| corrupt("paramètres de dérivation absents"))?
                } else {
                    Kdf::Aes {
                        rounds: aes_rounds.ok_or_else(|| corrupt("nombre de tours absent"))?,
                    }
                };
                return Ok(HeaderInfo {
                    major,
                    minor,
                    cipher,
                    kdf,
                });
            }
            FIELD_CIPHER => cipher = Some(parse_cipher(value)?),
            FIELD_TRANSFORM_ROUNDS if major == 3 => aes_rounds = Some(le_u64(value)?),
            FIELD_KDF_PARAMETERS if major >= 4 => kdf = Some(parse_kdf_parameters(value)?),
            _ => {}
        }
    }
    Err(corrupt("en-tête trop long ou sans fin"))
}

fn parse_cipher(value: &[u8]) -> Result<Cipher> {
    let uuid: [u8; 16] = value
        .try_into()
        .map_err(|_| corrupt("identifiant de chiffrement invalide"))?;
    Ok(match uuid {
        CIPHER_AES256 => Cipher::Aes256,
        CIPHER_CHACHA20 => Cipher::ChaCha20,
        CIPHER_TWOFISH => Cipher::Twofish,
        _ => Cipher::Unknown,
    })
}

/// Lit le dictionnaire des paramètres de dérivation (KDBX 4).
fn parse_kdf_parameters(data: &[u8]) -> Result<Kdf> {
    let mut r = Reader::new(data);
    let version = r.u16()?;
    if version & 0xFF00 != 0x0100 {
        return Err(corrupt("dictionnaire de paramètres : version inconnue"));
    }
    let mut keys: Vec<&[u8]> = Vec::new();
    let mut uuid = None;
    let mut rounds = None;
    let mut memory = None;
    let mut iterations = None;
    let mut parallelism = None;
    let mut algorithm_version = None;
    for _ in 0..MAX_DICTIONARY_ITEMS {
        let kind = r.u8()?;
        if kind == VD_END {
            if !r.is_empty() {
                return Err(corrupt(
                    "données après la fin du dictionnaire de paramètres",
                ));
            }
            let uuid = uuid.ok_or_else(|| corrupt("algorithme de dérivation absent"))?;
            return build_kdf(
                uuid,
                rounds,
                memory,
                iterations,
                parallelism,
                algorithm_version,
            );
        }
        let key_length = to_usize(r.u32()?)?;
        let key = r.take(key_length)?;
        let value_length = to_usize(r.u32()?)?;
        let value = r.take(value_length)?;

        // Longueur exacte selon le type : la bibliothèque échoue brutalement sur
        // une valeur numérique trop courte.
        let expected = match kind {
            VD_U32 | VD_I32 => Some(4),
            VD_U64 | VD_I64 => Some(8),
            VD_BOOL => Some(1),
            VD_STRING | VD_BYTES => None,
            _ => return Err(corrupt("type de paramètre inconnu")),
        };
        if expected.is_some_and(|n| n != value.len()) {
            return Err(corrupt("paramètre de longueur incorrecte"));
        }
        if keys.contains(&key) {
            return Err(corrupt("paramètre de dérivation en double"));
        }
        keys.push(key);

        match (key, kind) {
            (b"$UUID", VD_BYTES) => uuid = Some(value),
            (b"R", VD_U64) => rounds = Some(le_u64(value)?),
            (b"M", VD_U64) => memory = Some(le_u64(value)?),
            (b"I", VD_U64) => iterations = Some(le_u64(value)?),
            (b"P", VD_U32) => parallelism = Some(le_u32(value)?),
            (b"V", VD_U32) => algorithm_version = Some(le_u32(value)?),
            (b"$UUID" | b"R" | b"M" | b"I" | b"P" | b"V", _) => {
                return Err(corrupt("paramètre de dérivation d'un type inattendu"));
            }
            _ => {}
        }
    }
    Err(corrupt("dictionnaire de paramètres trop long ou sans fin"))
}

fn build_kdf(
    uuid: &[u8],
    rounds: Option<u64>,
    memory: Option<u64>,
    iterations: Option<u64>,
    parallelism: Option<u32>,
    version: Option<u32>,
) -> Result<Kdf> {
    let uuid: [u8; 16] = uuid
        .try_into()
        .map_err(|_| corrupt("identifiant de dérivation invalide"))?;
    let variant = match uuid {
        KDF_AES_KDBX3 | KDF_AES_KDBX4 => {
            return Ok(Kdf::Aes {
                rounds: rounds.ok_or_else(|| corrupt("nombre de tours absent"))?,
            });
        }
        KDF_ARGON2D => Argon2Variant::Argon2d,
        KDF_ARGON2ID => Argon2Variant::Argon2id,
        _ => {
            return Err(Error::Unsupported(
                "algorithme de dérivation inconnu".into(),
            ));
        }
    };
    Ok(Kdf::Argon2 {
        variant,
        memory_bytes: memory.ok_or_else(|| corrupt("mémoire d'Argon2 absente"))?,
        iterations: iterations.ok_or_else(|| corrupt("itérations d'Argon2 absentes"))?,
        parallelism: parallelism.ok_or_else(|| corrupt("parallélisme d'Argon2 absent"))?,
        version: version.ok_or_else(|| corrupt("version d'Argon2 absente"))?,
    })
}

fn corrupt(message: &str) -> Error {
    Error::Corrupt(message.to_owned())
}

fn to_usize(value: u32) -> Result<usize> {
    usize::try_from(value).map_err(|_| corrupt("longueur hors limites"))
}

fn le_u64(value: &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = value
        .try_into()
        .map_err(|_| corrupt("entier de 8 octets attendu"))?;
    Ok(u64::from_le_bytes(bytes))
}

fn le_u32(value: &[u8]) -> Result<u32> {
    let bytes: [u8; 4] = value
        .try_into()
        .map_err(|_| corrupt("entier de 4 octets attendu"))?;
    Ok(u32::from_le_bytes(bytes))
}

/// Lecture séquentielle bornée : aucune lecture hors du tampon.
struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn is_empty(&self) -> bool {
        self.position >= self.data.len()
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| corrupt("en-tête tronqué"))?;
        let slice = self
            .data
            .get(self.position..end)
            .ok_or_else(|| corrupt("en-tête tronqué"))?;
        self.position = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| corrupt("en-tête tronqué"))
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(u8::from_le_bytes(self.array()?))
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// En-tête KDBX 4.1 minimal construit à la main.
    fn header_with_dictionary(dictionary: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&SIGNATURE_1.to_le_bytes());
        out.extend_from_slice(&SIGNATURE_2_KDBX.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        push_field(&mut out, FIELD_CIPHER, &CIPHER_AES256);
        push_field(&mut out, FIELD_KDF_PARAMETERS, dictionary);
        push_field(&mut out, FIELD_END, b"\r\n\r\n");
        out
    }

    fn push_field(out: &mut Vec<u8>, id: u8, value: &[u8]) {
        out.push(id);
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
    }

    fn item(out: &mut Vec<u8>, kind: u8, key: &str, value: &[u8]) {
        out.push(kind);
        out.extend_from_slice(&(key.len() as u32).to_le_bytes());
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
    }

    fn argon2id_dictionary(memory: u64, iterations: u64, parallelism: u32) -> Vec<u8> {
        let mut d = vec![0x00, 0x01];
        item(&mut d, VD_BYTES, "$UUID", &KDF_ARGON2ID);
        item(&mut d, VD_BYTES, "S", &[7u8; 32]);
        item(&mut d, VD_U64, "M", &memory.to_le_bytes());
        item(&mut d, VD_U64, "I", &iterations.to_le_bytes());
        item(&mut d, VD_U32, "P", &parallelism.to_le_bytes());
        item(&mut d, VD_U32, "V", &0x13u32.to_le_bytes());
        d.push(VD_END);
        d
    }

    #[test]
    fn reads_argon2id_parameters() {
        let header = header_with_dictionary(&argon2id_dictionary(32 << 20, 10, 2));
        let info = inspect(&header).unwrap();
        assert_eq!(info.major, 4);
        assert_eq!(info.minor, 1);
        assert_eq!(info.cipher, Cipher::Aes256);
        assert_eq!(
            info.kdf,
            Kdf::Argon2 {
                variant: Argon2Variant::Argon2id,
                memory_bytes: 32 << 20,
                iterations: 10,
                parallelism: 2,
                version: 0x13
            }
        );
        OpenLimits::default().check(&info).unwrap();
    }

    #[test]
    fn rejects_excessive_parameters_before_any_derivation() {
        for (memory, iterations, parallelism) in [
            (1u64 << 41, 10, 2),
            (32 << 20, 1 << 40, 2),
            (32 << 20, 10, 100_000),
        ] {
            let header =
                header_with_dictionary(&argon2id_dictionary(memory, iterations, parallelism));
            let info = inspect(&header).unwrap();
            assert!(matches!(
                OpenLimits::default().check(&info),
                Err(Error::KdfRejected(_))
            ));
        }
        let header = header_with_dictionary(&argon2id_dictionary(128 << 20, 10, 2));
        let info = inspect(&header).unwrap();
        assert!(OpenLimits::default().check(&info).is_ok());
        assert!(OpenLimits::ios_autofill().check(&info).is_err());
    }

    #[test]
    fn rejects_duplicate_parameters() {
        // Deux valeurs de mémoire : la bibliothèque garderait la dernière,
        // un contrôle naïf la première. Le fichier est refusé.
        let mut d = vec![0x00, 0x01];
        item(&mut d, VD_BYTES, "$UUID", &KDF_ARGON2ID);
        item(&mut d, VD_U64, "M", &(32u64 << 20).to_le_bytes());
        item(&mut d, VD_U64, "M", &(1u64 << 45).to_le_bytes());
        item(&mut d, VD_U64, "I", &10u64.to_le_bytes());
        item(&mut d, VD_U32, "P", &2u32.to_le_bytes());
        item(&mut d, VD_U32, "V", &0x13u32.to_le_bytes());
        d.push(VD_END);
        assert!(matches!(
            inspect(&header_with_dictionary(&d)),
            Err(Error::Corrupt(_))
        ));
    }

    #[test]
    fn rejects_short_numeric_values() {
        let mut d = vec![0x00, 0x01];
        item(&mut d, VD_BYTES, "$UUID", &KDF_ARGON2ID);
        item(&mut d, VD_U32, "X", &[]);
        d.push(VD_END);
        assert!(matches!(
            inspect(&header_with_dictionary(&d)),
            Err(Error::Corrupt(_))
        ));
    }

    #[test]
    fn rejects_other_formats() {
        assert!(matches!(inspect(b""), Err(Error::Corrupt(_))));
        assert!(matches!(inspect(b"PK\x03\x04 zip"), Err(Error::Corrupt(_))));
        let mut kdb = Vec::new();
        kdb.extend_from_slice(&SIGNATURE_1.to_le_bytes());
        kdb.extend_from_slice(&SIGNATURE_2_KDB.to_le_bytes());
        assert!(matches!(inspect(&kdb), Err(Error::Unsupported(_))));
    }

    #[test]
    fn display_is_readable() {
        let kdf = Kdf::Argon2 {
            variant: Argon2Variant::Argon2id,
            memory_bytes: 32 << 20,
            iterations: 10,
            parallelism: 2,
            version: 0x13,
        };
        assert_eq!(kdf.to_string(), "Argon2id, 32 Mio, 10 itérations, 2 voies");
    }
}
