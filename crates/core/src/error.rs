//! Erreurs du noyau.
//!
//! Les messages sont en français ; les applications peuvent aussi reconnaître
//! chaque cas par sa variante pour afficher leur propre texte.

use thiserror::Error;

use crate::sync::SyncError;

/// Erreur renvoyée par le noyau.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// La phrase de passe ou le fichier clé ne correspond pas au coffre.
    #[error("clé incorrecte : la phrase de passe ou le fichier clé ne correspond pas au coffre")]
    WrongKey,

    /// Le fichier n'est pas un coffre KDBX lisible (tronqué, altéré, autre format).
    #[error("coffre illisible : {0}")]
    Corrupt(String),

    /// Format reconnu mais non pris en charge (KeePass 1.x, préversions de KDBX).
    #[error("format de coffre non pris en charge : {0}")]
    Unsupported(String),

    /// Paramètres de dérivation hors des plafonds : le coffre n'est pas ouvert.
    #[error("paramètres de dérivation refusés : {0}")]
    KdfRejected(String),

    /// Le fichier dépasse la taille maximale acceptée.
    #[error("fichier trop volumineux : {size} octets (maximum {max})")]
    TooLarge {
        /// Taille du fichier, en octets.
        size: u64,
        /// Taille maximale acceptée, en octets.
        max: u64,
    },

    /// Écriture, relecture ou remplacement du fichier impossible.
    #[error("enregistrement impossible : {0}")]
    Save(String),

    /// Aucune entrée ne porte cet identifiant.
    #[error("entrée introuvable : {0}")]
    EntryNotFound(String),

    /// Les deux fichiers ne sont pas des versions du même coffre.
    #[error("fusion refusée : les deux fichiers ne sont pas des versions du même coffre")]
    DifferentVaults,

    /// La fusion a échoué ; aucun des deux coffres n'a été modifié.
    #[error("fusion impossible : {0}")]
    Merge(String),

    /// Paramètre invalide.
    #[error("paramètre invalide : {0}")]
    InvalidInput(String),

    /// Le fichier existe déjà.
    #[error("le fichier existe déjà : {0}")]
    AlreadyExists(String),

    /// Aucun coffre à l'emplacement indiqué.
    #[error("coffre introuvable : {0}")]
    VaultNotFound(String),

    /// Aucun fichier clé à l'emplacement indiqué.
    #[error("fichier clé introuvable : {0}")]
    KeyFileNotFound(String),

    /// Fichier clé XML 2.0 dont la somme de contrôle ne correspond pas : il a
    /// été modifié ou endommagé.
    #[error("fichier clé endommagé : sa somme de contrôle ne correspond pas à son contenu")]
    KeyFileCorrupt,

    /// Erreur d'entrée-sortie du système de fichiers.
    #[error("erreur d'entrée-sortie : {0}")]
    Io(#[from] std::io::Error),

    /// Erreur pendant la synchronisation avec le serveur.
    #[error(transparent)]
    Sync(#[from] SyncError),

    /// Le générateur aléatoire du système est indisponible.
    #[error("générateur aléatoire du système indisponible")]
    Random,
}

/// Résultat du noyau.
pub type Result<T, E = Error> = std::result::Result<T, E>;
