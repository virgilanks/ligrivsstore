//! Erreurs présentées à l'interface.

use serde::Serialize;

/// Erreur d'une commande : un code stable, pour que l'interface réagisse au
/// bon cas, et un message en français, prêt à afficher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppError {
    /// Code stable (par exemple `cle_incorrecte`).
    pub code: &'static str,
    /// Message en français.
    pub message: String,
}

impl AppError {
    /// Crée une erreur.
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Aucun coffre n'est ouvert.
    pub fn locked() -> Self {
        Self::new(
            "verrouille",
            "le coffre est verrouillé : déverrouillez-le d'abord",
        )
    }

    /// Erreur interne inattendue (tâche interrompue, verrou empoisonné…).
    pub fn internal(detail: impl std::fmt::Display) -> Self {
        Self::new("interne", format!("erreur interne : {detail}"))
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AppError {}

impl From<ligrivsstore_core::Error> for AppError {
    fn from(error: ligrivsstore_core::Error) -> Self {
        use ligrivsstore_core::Error as E;
        let code = match &error {
            E::WrongKey => "cle_incorrecte",
            E::VaultNotFound(_) => "coffre_introuvable",
            E::KeyFileNotFound(_) => "fichier_cle_introuvable",
            E::KeyFileCorrupt => "fichier_cle_endommage",
            E::AlreadyExists(_) => "existe_deja",
            E::EntryNotFound(_) => "entree_introuvable",
            E::InvalidInput(_) => "parametre_invalide",
            E::Corrupt(_) | E::Unsupported(_) | E::KdfRejected(_) | E::TooLarge { .. } => {
                "coffre_illisible"
            }
            E::Save(_) => "enregistrement",
            E::Io(_) => "entree_sortie",
            E::Sync(_) => "synchronisation",
            _ => "autre",
        };
        Self::new(code, error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_errors_keep_their_french_message_and_get_a_stable_code() {
        let error = AppError::from(ligrivsstore_core::Error::WrongKey);
        assert_eq!(error.code, "cle_incorrecte");
        assert!(error.message.contains("clé incorrecte"));
        let error = AppError::from(ligrivsstore_core::Error::VaultNotFound("c.kdbx".into()));
        assert_eq!(error.code, "coffre_introuvable");
        assert!(error.message.contains("c.kdbx"));
    }

    #[test]
    fn errors_serialize_for_the_interface() {
        let json = serde_json::to_string(&AppError::locked()).unwrap();
        assert!(json.contains("\"code\":\"verrouille\""), "{json}");
    }
}
