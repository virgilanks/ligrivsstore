//! État observable de la session, lisible sans attendre la session.
//!
//! Pendant une synchronisation, la session est occupée : l'interface lit
//! alors cet état (verrouillé ou non, synchronisation en cours, dernier
//! bilan) pour l'afficher sans bloquer.

use std::sync::Mutex;

use chrono::Utc;

use crate::autopilot::LockReason;
use crate::dto::{Activity, SyncStatusView};
use crate::synchro::SyncOutcome;

/// État partagé entre la session, le pilote et l'interface.
#[derive(Debug, Default)]
pub struct Monitor {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    unlocked: bool,
    lock_reason: Option<LockReason>,
    lock_minutes: u32,
    revision: u64,
    configured: bool,
    running: bool,
    last_outcome: Option<SyncOutcome>,
    last_success_utc: Option<String>,
}

impl Monitor {
    fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        f(&mut state)
    }

    /// Coffre ouvert ; `configured` : synchronisation réglée dans ce coffre.
    pub fn unlocked(&self, configured: bool, last_success_utc: Option<String>) {
        self.with(|s| {
            s.unlocked = true;
            s.lock_reason = None;
            s.configured = configured;
            s.last_outcome = None;
            s.last_success_utc = last_success_utc;
            s.revision += 1;
        });
    }

    /// Coffre verrouillé.
    pub fn locked(&self, reason: LockReason, lock_minutes: u32) {
        self.with(|s| {
            s.unlocked = false;
            s.lock_reason = Some(reason);
            s.lock_minutes = lock_minutes;
            s.running = false;
            s.last_outcome = None;
        });
    }

    /// Vrai si le coffre est ouvert.
    pub fn is_unlocked(&self) -> bool {
        self.with(|s| s.unlocked)
    }

    /// Synchronisation réglée (ou non) dans le coffre ouvert.
    pub fn set_configured(&self, configured: bool) {
        self.with(|s| s.configured = configured);
    }

    /// Le contenu du coffre a changé hors de l'interface (fusion,
    /// restauration) : l'interface doit relire la liste.
    pub fn bump_revision(&self) {
        self.with(|s| s.revision += 1);
    }

    /// Une synchronisation commence.
    pub fn sync_started(&self) {
        self.with(|s| s.running = true);
    }

    /// Bilan d'une synchronisation.
    pub fn sync_finished(&self, outcome: &SyncOutcome) {
        self.with(|s| {
            s.running = false;
            if let SyncOutcome::Done { merged, .. } = outcome {
                s.last_success_utc = Some(Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string());
                if *merged > 0 {
                    s.revision += 1;
                }
            }
            if !matches!(outcome, SyncOutcome::Locked) {
                s.last_outcome = Some(outcome.clone());
            }
        });
    }

    /// Instantané pour l'interface.
    pub fn activity(&self) -> Activity {
        self.with(|s| Activity {
            unlocked: s.unlocked,
            lock_message: s.lock_reason.map(|r| r.message(s.lock_minutes)),
            revision: s.revision,
            sync: sync_view(s),
        })
    }
}

fn sync_view(s: &State) -> SyncStatusView {
    let (state, message) = if !s.configured {
        ("non_configuree", None)
    } else if s.running {
        ("en_cours", None)
    } else {
        match &s.last_outcome {
            None => ("en_attente", None),
            Some(SyncOutcome::Done { .. }) => ("a_jour", None),
            Some(SyncOutcome::Offline(m)) => ("hors_ligne", Some(m.clone())),
            Some(SyncOutcome::Suspended(m)) => ("suspendue", Some(m.clone())),
            Some(SyncOutcome::Failed(m)) => ("erreur", Some(m.clone())),
            Some(SyncOutcome::NotConfigured | SyncOutcome::Locked) => ("non_configuree", None),
        }
    };
    SyncStatusView {
        configured: s.configured,
        state,
        last_success: s.last_success_utc.clone(),
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_follow_the_session() {
        let monitor = Monitor::default();
        assert!(!monitor.activity().unlocked);
        monitor.unlocked(true, None);
        let first = monitor.activity();
        assert_eq!(first.sync.state, "en_attente");
        monitor.sync_started();
        assert_eq!(monitor.activity().sync.state, "en_cours");
        monitor.sync_finished(&SyncOutcome::Done {
            downloaded: true,
            uploaded: false,
            merged: 2,
        });
        let after = monitor.activity();
        assert_eq!(after.sync.state, "a_jour");
        assert!(after.sync.last_success.is_some());
        assert!(after.revision > first.revision, "la liste doit être relue");

        monitor.sync_finished(&SyncOutcome::Suspended("refus".into()));
        let suspended = monitor.activity();
        assert_eq!(suspended.sync.state, "suspendue");
        assert_eq!(suspended.sync.message.as_deref(), Some("refus"));

        monitor.locked(LockReason::Inactivity, 5);
        let locked = monitor.activity();
        assert!(!locked.unlocked);
        assert_eq!(
            locked.lock_message.as_deref(),
            Some("Coffre verrouillé après 5 minutes d'inactivité.")
        );
        monitor.unlocked(false, None);
        assert_eq!(monitor.activity().sync.state, "non_configuree");
        assert_eq!(monitor.activity().lock_message, None);
    }
}
