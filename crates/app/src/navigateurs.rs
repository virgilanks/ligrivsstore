//! Navigateurs appairés et demandes d'appairage en attente (note de
//! conception n° 3, section 6.2).
//!
//! Un navigateur appairé est connu par la clé publique permanente de son
//! extension et par l'origine de l'extension, que le relais tient du
//! navigateur. Ces données ne sont pas secrètes : elles sont gardées en clair
//! dans `navigateurs.json`, à côté des réglages. La clé privée de
//! l'application, elle, est protégée par DPAPI (voir [`crate::liaison`]).
//!
//! Une demande d'appairage attend la décision de l'utilisateur dans
//! l'application, deux minutes au plus ; trois demandes au plus attendent en
//! même temps.

use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use chrono::Utc;
use ligrivsstore_protocol::PairState;
use serde::{Deserialize, Serialize};

use crate::dto::{BrowserView, PairingRequestView};
use crate::error::AppError;

/// Délai de réponse à une demande d'appairage.
pub const PAIRING_TIMEOUT: Duration = Duration::from_secs(120);

/// Demandes en attente au plus.
pub const MAX_PENDING: usize = 3;

/// Fichier des navigateurs appairés, dans le dossier des réglages.
pub const FILE_NAME: &str = "navigateurs.json";

/// Navigateur appairé.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedBrowser {
    /// Numéro, attribué à l'appairage.
    pub id: String,
    /// Nom donné par l'extension (« Chrome », « Edge »).
    pub browser: String,
    /// Origine de l'extension (`chrome-extension://<id>/`).
    pub origin: String,
    /// Clé publique permanente de l'extension (Base64).
    pub client_key: String,
    /// Empreinte confirmée à l'appairage.
    pub fingerprint: String,
    /// Date de l'appairage (UTC, ISO 8601).
    pub paired_utc: String,
    /// Dernière session ouverte (UTC, ISO 8601).
    #[serde(default)]
    pub last_seen_utc: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Stored {
    #[serde(default)]
    browsers: Vec<PairedBrowser>,
}

#[derive(Debug)]
struct Pending {
    id: String,
    browser: String,
    origin: String,
    client_key: String,
    fingerprint: String,
    created: Instant,
    decision: Option<PairState>,
}

#[derive(Debug)]
struct Inner {
    stored: Stored,
    pending: Vec<Pending>,
}

/// Registre des navigateurs, partagé entre la liaison et l'interface.
#[derive(Debug)]
pub struct Browsers {
    path: PathBuf,
    inner: Mutex<Inner>,
    decided: Condvar,
}

fn now_utc() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn random_id() -> Result<String, AppError> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(AppError::internal)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

impl Browsers {
    /// Lit le registre du dossier des réglages ; un fichier illisible vaut un
    /// registre vide (il faudra appairer de nouveau).
    pub fn load(config_dir: &Path) -> Self {
        let path = config_dir.join(FILE_NAME);
        let stored = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self {
            path,
            inner: Mutex::new(Inner {
                stored,
                pending: Vec::new(),
            }),
            decided: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        expire(&mut inner);
        inner
    }

    fn save(&self, inner: &Inner) -> Result<(), AppError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(AppError::internal)?;
        }
        let json = serde_json::to_vec_pretty(&inner.stored).map_err(AppError::internal)?;
        ligrivsstore_core::storage::replace_file(&self.path, &json)?;
        Ok(())
    }

    /// Navigateurs appairés, pour l'interface.
    pub fn list(&self) -> Vec<BrowserView> {
        self.lock()
            .stored
            .browsers
            .iter()
            .map(|b| BrowserView {
                id: b.id.clone(),
                browser: b.browser.clone(),
                fingerprint: b.fingerprint.clone(),
                paired: b.paired_utc.clone(),
                last_seen: b.last_seen_utc.clone(),
            })
            .collect()
    }

    /// Demandes en attente de décision, pour l'interface.
    pub fn pending(&self) -> Vec<PairingRequestView> {
        self.lock()
            .pending
            .iter()
            .filter(|p| p.decision.is_none())
            .map(|p| PairingRequestView {
                id: p.id.clone(),
                browser: p.browser.clone(),
                fingerprint: p.fingerprint.clone(),
                seconds_left: PAIRING_TIMEOUT
                    .saturating_sub(p.created.elapsed())
                    .as_secs(),
            })
            .collect()
    }

    /// Nombre de demandes en attente de décision.
    pub fn pending_count(&self) -> usize {
        self.lock()
            .pending
            .iter()
            .filter(|p| p.decision.is_none())
            .count()
    }

    /// Enregistre une demande d'appairage ; renvoie son numéro.
    pub fn request(
        &self,
        browser: &str,
        origin: &str,
        client_key: &str,
        fingerprint: &str,
    ) -> Result<String, AppError> {
        let mut inner = self.lock();
        if inner
            .pending
            .iter()
            .filter(|p| p.decision.is_none())
            .count()
            >= MAX_PENDING
        {
            return Err(AppError::new(
                "trop_de_demandes",
                "trop de demandes d'appairage en attente : répondez d'abord à celles affichées dans l'application",
            ));
        }
        let id = random_id()?;
        inner.pending.push(Pending {
            id: id.clone(),
            browser: browser.to_owned(),
            origin: origin.to_owned(),
            client_key: client_key.to_owned(),
            fingerprint: fingerprint.to_owned(),
            created: Instant::now(),
            decision: None,
        });
        Ok(id)
    }

    /// Attend la décision sur une demande, `timeout` au plus.
    pub fn wait_decision(&self, id: &str, timeout: Duration) -> PairState {
        let deadline = Instant::now() + timeout;
        let mut inner = self.lock();
        loop {
            let decision = inner
                .pending
                .iter()
                .find(|p| p.id == id)
                .map(|p| p.decision);
            match decision {
                Some(Some(state)) => {
                    inner.pending.retain(|p| p.id != id);
                    return state;
                }
                None => return PairState::Expired,
                Some(None) => {}
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                inner.pending.retain(|p| p.id != id);
                return PairState::Expired;
            }
            inner = self
                .decided
                .wait_timeout(inner, left)
                .map(|(guard, _)| guard)
                .unwrap_or_else(|p| p.into_inner().0);
            expire(&mut inner);
        }
    }

    /// Décision de l'utilisateur : confirmer (le navigateur est retenu) ou
    /// refuser.
    pub fn decide(&self, id: &str, confirm: bool) -> Result<(), AppError> {
        let mut inner = self.lock();
        let Some(pending) = inner
            .pending
            .iter_mut()
            .find(|p| p.id == id && p.decision.is_none())
        else {
            return Err(AppError::new(
                "demande_expiree",
                "cette demande d'appairage a expiré : relancez l'appairage depuis l'extension",
            ));
        };
        if !confirm {
            pending.decision = Some(PairState::Refused);
            self.decided.notify_all();
            return Ok(());
        }
        pending.decision = Some(PairState::Confirmed);
        let paired = PairedBrowser {
            id: pending.id.clone(),
            browser: pending.browser.clone(),
            origin: pending.origin.clone(),
            client_key: pending.client_key.clone(),
            fingerprint: pending.fingerprint.clone(),
            paired_utc: now_utc(),
            last_seen_utc: None,
        };
        // Une même extension appairée de nouveau remplace l'ancien appairage.
        inner
            .stored
            .browsers
            .retain(|b| b.client_key != paired.client_key);
        inner.stored.browsers.push(paired);
        self.decided.notify_all();
        self.save(&inner)
    }

    /// Révoque un navigateur : ses sessions sont refusées dès le message
    /// suivant, et il devra être appairé de nouveau.
    pub fn revoke(&self, id: &str) -> Result<(), AppError> {
        let mut inner = self.lock();
        let before = inner.stored.browsers.len();
        inner.stored.browsers.retain(|b| b.id != id);
        if inner.stored.browsers.len() == before {
            return Err(AppError::new("introuvable", "navigateur inconnu"));
        }
        self.save(&inner)
    }

    /// Oublie tous les navigateurs (clé de l'application renouvelée).
    pub fn forget_all(&self) -> Result<(), AppError> {
        let mut inner = self.lock();
        inner.stored.browsers.clear();
        self.save(&inner)
    }

    /// Navigateur appairé avec cette clé, depuis cette origine.
    pub fn find(&self, client_key: &str, origin: &str) -> Option<PairedBrowser> {
        self.lock()
            .stored
            .browsers
            .iter()
            .find(|b| b.client_key == client_key && b.origin == origin)
            .cloned()
    }

    /// Le navigateur est-il toujours appairé ?
    pub fn is_paired(&self, id: &str) -> bool {
        self.lock().stored.browsers.iter().any(|b| b.id == id)
    }

    /// Note l'ouverture d'une session.
    pub fn touch(&self, id: &str) {
        let mut inner = self.lock();
        if let Some(browser) = inner.stored.browsers.iter_mut().find(|b| b.id == id) {
            browser.last_seen_utc = Some(now_utc());
            let _ = self.save(&inner);
        }
    }
}

/// Les demandes sans réponse dans le délai expirent ; celles dont personne
/// n'attend plus la décision (liaison fermée) finissent par disparaître.
fn expire(inner: &mut Inner) {
    for pending in &mut inner.pending {
        if pending.decision.is_none() && pending.created.elapsed() >= PAIRING_TIMEOUT {
            pending.decision = Some(PairState::Expired);
        }
    }
    inner
        .pending
        .retain(|p| p.created.elapsed() < 2 * PAIRING_TIMEOUT);
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use super::*;

    const ORIGIN: &str = "chrome-extension://pbjfabapbnileccikicpifdnhkocnlbb/";

    #[test]
    fn a_confirmed_request_is_kept_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let browsers = Arc::new(Browsers::load(dir.path()));
        let id = browsers.request("Chrome", ORIGIN, "CLE", "1 2 3").unwrap();
        assert_eq!(browsers.pending_count(), 1);
        let waiting = Arc::clone(&browsers);
        let waiter = {
            let id = id.clone();
            thread::spawn(move || waiting.wait_decision(&id, Duration::from_secs(10)))
        };
        browsers.decide(&id, true).unwrap();
        assert_eq!(waiter.join().unwrap(), PairState::Confirmed);
        assert_eq!(browsers.pending_count(), 0);

        let reloaded = Browsers::load(dir.path());
        let listed = reloaded.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].browser, "Chrome");
        assert_eq!(listed[0].fingerprint, "1 2 3");
        let found = reloaded.find("CLE", ORIGIN).unwrap();
        assert!(reloaded.find("CLE", "chrome-extension://autre/").is_none());
        reloaded.touch(&found.id);
        assert!(reloaded.list()[0].last_seen.is_some());
        reloaded.revoke(&found.id).unwrap();
        assert!(!reloaded.is_paired(&found.id));
        assert!(Browsers::load(dir.path()).list().is_empty());
    }

    #[test]
    fn refused_and_unanswered_requests_leave_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let browsers = Arc::new(Browsers::load(dir.path()));
        let refused = browsers.request("Edge", ORIGIN, "A", "f").unwrap();
        browsers.decide(&refused, false).unwrap();
        assert_eq!(
            browsers.wait_decision(&refused, Duration::from_secs(1)),
            PairState::Refused
        );
        let silent = browsers.request("Edge", ORIGIN, "B", "f").unwrap();
        assert_eq!(
            browsers.wait_decision(&silent, Duration::from_millis(50)),
            PairState::Expired
        );
        assert!(browsers.decide(&silent, true).is_err(), "trop tard");
        assert!(browsers.list().is_empty());
        assert_eq!(browsers.pending_count(), 0);
    }

    #[test]
    fn requests_are_limited_and_a_new_pairing_replaces_the_old_one() {
        let dir = tempfile::tempdir().unwrap();
        let browsers = Browsers::load(dir.path());
        let ids: Vec<String> = (0..MAX_PENDING)
            .map(|i| {
                browsers
                    .request("Chrome", ORIGIN, &format!("K{i}"), "f")
                    .unwrap()
            })
            .collect();
        assert_eq!(
            browsers
                .request("Chrome", ORIGIN, "K9", "f")
                .unwrap_err()
                .code,
            "trop_de_demandes"
        );
        browsers.decide(&ids[0], true).unwrap();
        // Même clé, nouvel appairage : un seul navigateur listé.
        let again = browsers.request("Chrome", ORIGIN, "K0", "g").unwrap();
        browsers.decide(&again, true).unwrap();
        let listed = browsers.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].fingerprint, "g");
    }

    #[test]
    fn a_damaged_file_means_no_paired_browser() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE_NAME), b"{ illisible").unwrap();
        assert!(Browsers::load(dir.path()).list().is_empty());
    }
}
