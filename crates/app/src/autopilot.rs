//! Pilote : ce qui se décide avec le temps.
//!
//! - verrouillage après une période d'inactivité (5 minutes par défaut,
//!   réglable de 1 à 60), à la mise en veille et au verrouillage de la
//!   session ;
//! - synchronisation à l'ouverture, 10 secondes après la dernière
//!   modification, toutes les 15 minutes et à la demande ; nouvel essai
//!   espacé quand le serveur est injoignable ; aucun essai après un refus
//!   d'identifiants ;
//! - effacement du presse-papiers après une copie.
//!
//! Le pilote n'a ni fil ni horloge : la coquille l'interroge chaque seconde
//! avec l'heure ([`Autopilot::tick`]) et exécute les actions rendues. Tout se
//! vérifie ainsi par des essais, sans attendre.

use std::time::{Duration, Instant, SystemTime};

use ligrivsstore_win::SystemEvent;
use ligrivsstore_win::clipboard::CopyToken;

use crate::synchro::SyncOutcome;

/// Période entre deux synchronisations.
pub const SYNC_INTERVAL: Duration = Duration::from_secs(15 * 60);
/// Attente après la dernière modification, pour regrouper les saisies.
pub const SYNC_DEBOUNCE: Duration = Duration::from_secs(10);
/// Attentes successives quand le serveur est injoignable.
pub const OFFLINE_RETRIES: [Duration; 3] = [
    Duration::from_secs(2 * 60),
    Duration::from_secs(5 * 60),
    Duration::from_secs(15 * 60),
];
/// Écart entre deux interrogations au-delà duquel le système a dormi.
pub const SLEEP_GAP: Duration = Duration::from_secs(30);

/// Motif d'un verrouillage, affiché à l'écran de déverrouillage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    /// Verrouillage demandé.
    Manual,
    /// Inactivité prolongée.
    Inactivity,
    /// Session Windows verrouillée, fermée ou déconnectée.
    SessionLocked,
    /// Mise en veille (annoncée, ou constatée au réveil).
    Sleep,
}

impl LockReason {
    /// Message pour l'écran de déverrouillage.
    pub fn message(self, lock_minutes: u32) -> String {
        match self {
            Self::Manual => "Coffre verrouillé.".to_owned(),
            Self::Inactivity => format!(
                "Coffre verrouillé après {lock_minutes} minute{} d'inactivité.",
                if lock_minutes > 1 { "s" } else { "" }
            ),
            Self::SessionLocked => "Coffre verrouillé avec la session Windows.".to_owned(),
            Self::Sleep => "Coffre verrouillé à la mise en veille.".to_owned(),
        }
    }
}

/// Action demandée à la coquille.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Verrouiller le coffre.
    Lock(LockReason),
    /// Lancer une synchronisation.
    Sync,
    /// Vider le presse-papiers s'il contient toujours cette copie.
    ClearClipboard(CopyToken),
}

/// Pilote d'une session.
#[derive(Debug)]
pub struct Autopilot {
    lock_after: Duration,
    unlocked: bool,
    last_activity: Instant,
    last_tick: Option<(Instant, SystemTime)>,
    next_sync: Option<Instant>,
    offline_failures: usize,
    suspended: bool,
    sync_running: bool,
    clipboard: Option<(CopyToken, Instant)>,
}

impl Autopilot {
    /// Pilote d'un coffre verrouillé.
    pub fn new(lock_after: Duration, now: Instant) -> Self {
        Self {
            lock_after,
            unlocked: false,
            last_activity: now,
            last_tick: None,
            next_sync: None,
            offline_failures: 0,
            suspended: false,
            sync_running: false,
            clipboard: None,
        }
    }

    /// Change le délai de verrouillage.
    pub fn set_lock_after(&mut self, lock_after: Duration) {
        self.lock_after = lock_after;
    }

    /// Délai de verrouillage.
    pub fn lock_after(&self) -> Duration {
        self.lock_after
    }

    /// Le coffre vient d'être ouvert : synchroniser tout de suite.
    pub fn on_unlocked(&mut self, now: Instant) {
        self.unlocked = true;
        self.last_activity = now;
        self.offline_failures = 0;
        self.suspended = false;
        self.next_sync = Some(now);
    }

    /// Le coffre vient d'être verrouillé.
    pub fn on_locked(&mut self) {
        self.unlocked = false;
        self.next_sync = None;
        self.sync_running = false;
    }

    /// Action de l'utilisateur dans l'application.
    pub fn on_activity(&mut self, now: Instant) {
        self.last_activity = now;
    }

    /// Le coffre vient d'être modifié : synchroniser après un court délai.
    pub fn on_modified(&mut self, now: Instant) {
        self.last_activity = now;
        if !self.suspended {
            self.next_sync = Some(now + SYNC_DEBOUNCE);
        }
    }

    /// Synchronisation demandée par l'utilisateur.
    pub fn on_sync_requested(&mut self, now: Instant) {
        self.last_activity = now;
        // Une demande explicite suit une nouvelle saisie des identifiants ou
        // un retour du réseau : on ne garde pas les attentes accumulées.
        self.offline_failures = 0;
        self.next_sync = Some(now);
    }

    /// Les identifiants du serveur viennent d'être saisis de nouveau.
    pub fn on_credentials_changed(&mut self, now: Instant) {
        self.suspended = false;
        self.on_sync_requested(now);
    }

    /// Une synchronisation commence (déjà noté quand [`Autopilot::tick`] la
    /// demande).
    pub fn on_sync_started(&mut self) {
        self.sync_running = true;
        self.next_sync = None;
    }

    /// Bilan d'une synchronisation : prochaine échéance.
    pub fn on_sync_finished(&mut self, now: Instant, outcome: &SyncOutcome) {
        self.sync_running = false;
        let pending = self.next_sync.take();
        self.next_sync = match outcome {
            SyncOutcome::Done { .. } | SyncOutcome::NotConfigured | SyncOutcome::Failed(_) => {
                self.offline_failures = 0;
                // Une modification faite pendant l'échange garde son échéance.
                Some(pending.map_or(now + SYNC_INTERVAL, |p| p.min(now + SYNC_INTERVAL)))
            }
            SyncOutcome::Offline(_) => {
                let wait = OFFLINE_RETRIES
                    .get(self.offline_failures)
                    .or(OFFLINE_RETRIES.last())
                    .copied()
                    .unwrap_or(SYNC_INTERVAL);
                self.offline_failures += 1;
                Some(now + wait)
            }
            SyncOutcome::Suspended(_) => {
                self.suspended = true;
                None
            }
            SyncOutcome::Locked => None,
        };
    }

    /// Une copie vient d'être faite : l'effacer après `delay`.
    pub fn on_copied(&mut self, token: CopyToken, now: Instant, delay: Duration) {
        self.last_activity = now;
        self.clipboard = Some((token, now + delay));
    }

    /// Événement du système.
    pub fn on_system_event(&mut self, event: SystemEvent) -> Option<Action> {
        if !self.unlocked {
            return None;
        }
        Some(Action::Lock(match event {
            SystemEvent::SessionLocked => LockReason::SessionLocked,
            SystemEvent::Suspending => LockReason::Sleep,
        }))
    }

    /// Interrogation périodique (chaque seconde environ) : actions à mener
    /// maintenant. `wall` est l'heure du système, pour reconnaître un réveil.
    pub fn tick(&mut self, now: Instant, wall: SystemTime) -> Vec<Action> {
        let mut actions = Vec::new();
        if let Some((token, due)) = self.clipboard
            && now >= due
        {
            self.clipboard = None;
            actions.push(Action::ClearClipboard(token));
        }
        let slept = self.last_tick.is_some_and(|(tick, tick_wall)| {
            let monotonic = now.saturating_duration_since(tick);
            let elapsed = wall.duration_since(tick_wall).unwrap_or_default();
            monotonic > SLEEP_GAP || elapsed > monotonic + SLEEP_GAP
        });
        self.last_tick = Some((now, wall));
        if !self.unlocked {
            return actions;
        }
        if slept {
            actions.push(Action::Lock(LockReason::Sleep));
        } else if now.saturating_duration_since(self.last_activity) >= self.lock_after {
            actions.push(Action::Lock(LockReason::Inactivity));
        } else if !self.sync_running
            && !self.suspended
            && self.next_sync.is_some_and(|due| now >= due)
        {
            // Un seul échange à la fois : la coquille rend son bilan par
            // `on_sync_finished`.
            self.on_sync_started();
            actions.push(Action::Sync);
        }
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    struct Clock {
        start: Instant,
        wall: SystemTime,
    }

    impl Clock {
        fn new() -> Self {
            Self {
                start: Instant::now(),
                wall: SystemTime::now(),
            }
        }
        fn at(&self, offset: Duration) -> (Instant, SystemTime) {
            (self.start + offset, self.wall + offset)
        }
    }

    fn run(
        pilot: &mut Autopilot,
        clock: &Clock,
        from: Duration,
        to: Duration,
    ) -> Vec<(Duration, Action)> {
        let mut seen = Vec::new();
        let mut t = from;
        while t <= to {
            let (now, wall) = clock.at(t);
            for action in pilot.tick(now, wall) {
                seen.push((t, action));
            }
            t += Duration::from_secs(1);
        }
        seen
    }

    #[test]
    fn locks_after_the_inactivity_delay_but_not_while_the_user_is_active() {
        let clock = Clock::new();
        let mut pilot = Autopilot::new(5 * MINUTE, clock.start);
        pilot.on_unlocked(clock.start);
        pilot.on_sync_started();
        pilot.on_sync_finished(clock.start, &SyncOutcome::NotConfigured);
        // Activité à 4 minutes : pas de verrouillage à 5 minutes.
        assert!(run(&mut pilot, &clock, Duration::ZERO, 4 * MINUTE).is_empty());
        pilot.on_activity(clock.at(4 * MINUTE).0);
        let seen = run(
            &mut pilot,
            &clock,
            4 * MINUTE + Duration::from_secs(1),
            10 * MINUTE,
        );
        let (when, action) = seen.first().copied().unwrap();
        assert_eq!(action, Action::Lock(LockReason::Inactivity));
        assert_eq!(when, 9 * MINUTE);
        pilot.on_locked();
        assert!(run(&mut pilot, &clock, 10 * MINUTE, 30 * MINUTE).is_empty());
    }

    #[test]
    fn a_gap_between_ticks_means_the_system_slept() {
        let clock = Clock::new();
        let mut pilot = Autopilot::new(60 * MINUTE, clock.start);
        pilot.on_unlocked(clock.start);
        pilot.on_sync_started();
        pilot.on_sync_finished(clock.start, &SyncOutcome::NotConfigured);
        let (now, wall) = clock.at(Duration::from_secs(1));
        assert!(pilot.tick(now, wall).is_empty());
        // Réveil : l'horloge du système a avancé de deux heures, l'horloge
        // monotone de deux secondes (elle s'arrête pendant la veille sur
        // certains systèmes).
        let (now, _) = clock.at(Duration::from_secs(3));
        let (_, wall) = clock.at(Duration::from_secs(2 * 3600));
        assert_eq!(pilot.tick(now, wall), [Action::Lock(LockReason::Sleep)]);
        // Et si c'est l'horloge monotone qui a avancé.
        let mut pilot = Autopilot::new(60 * MINUTE, clock.start);
        pilot.on_unlocked(clock.start);
        pilot.on_sync_started();
        pilot.on_sync_finished(clock.start, &SyncOutcome::NotConfigured);
        let (now, wall) = clock.at(Duration::from_secs(1));
        pilot.tick(now, wall);
        let (now, wall) = clock.at(Duration::from_secs(600));
        assert_eq!(pilot.tick(now, wall), [Action::Lock(LockReason::Sleep)]);
    }

    #[test]
    fn system_events_lock_only_an_unlocked_vault() {
        let clock = Clock::new();
        let mut pilot = Autopilot::new(5 * MINUTE, clock.start);
        assert_eq!(pilot.on_system_event(SystemEvent::SessionLocked), None);
        pilot.on_unlocked(clock.start);
        assert_eq!(
            pilot.on_system_event(SystemEvent::SessionLocked),
            Some(Action::Lock(LockReason::SessionLocked))
        );
        assert_eq!(
            pilot.on_system_event(SystemEvent::Suspending),
            Some(Action::Lock(LockReason::Sleep))
        );
    }

    #[test]
    fn sync_at_opening_after_modifications_and_every_fifteen_minutes() {
        let clock = Clock::new();
        let mut pilot = Autopilot::new(60 * MINUTE, clock.start);
        pilot.on_unlocked(clock.start);
        let (now, wall) = clock.at(Duration::ZERO);
        assert_eq!(pilot.tick(now, wall), [Action::Sync]);
        pilot.on_sync_started();
        // Pendant l'échange, rien d'autre n'est lancé.
        assert!(
            run(
                &mut pilot,
                &clock,
                Duration::from_secs(1),
                Duration::from_secs(3)
            )
            .is_empty()
        );
        let done = SyncOutcome::Done {
            downloaded: true,
            uploaded: false,
            merged: 0,
        };
        pilot.on_sync_finished(clock.at(Duration::from_secs(3)).0, &done);

        // Deux modifications rapprochées : un seul échange, 10 s après la
        // dernière.
        pilot.on_modified(clock.at(Duration::from_secs(20)).0);
        pilot.on_modified(clock.at(Duration::from_secs(25)).0);
        let seen = run(
            &mut pilot,
            &clock,
            Duration::from_secs(4),
            Duration::from_secs(40),
        );
        assert_eq!(seen, [(Duration::from_secs(35), Action::Sync)]);
        pilot.on_sync_started();
        pilot.on_sync_finished(clock.at(Duration::from_secs(36)).0, &done);

        // Sans modification : 15 minutes plus tard (l'utilisateur reste actif).
        let mut t = Duration::from_secs(37);
        let mut syncs = Vec::new();
        while t < Duration::from_secs(36) + SYNC_INTERVAL + Duration::from_secs(5) {
            let (now, wall) = clock.at(t);
            pilot.on_activity(now);
            for action in pilot.tick(now, wall) {
                syncs.push((t, action));
            }
            t += Duration::from_secs(1);
        }
        assert_eq!(
            syncs,
            [(Duration::from_secs(36) + SYNC_INTERVAL, Action::Sync)]
        );
    }

    #[test]
    fn offline_retries_are_spaced_and_suspension_stops_everything() {
        let clock = Clock::new();
        let mut pilot = Autopilot::new(120 * MINUTE, clock.start);
        pilot.on_unlocked(clock.start);
        let mut t = Duration::ZERO;
        let mut gaps = Vec::new();
        let mut last = Duration::ZERO;
        while gaps.len() < 4 {
            let (now, wall) = clock.at(t);
            pilot.on_activity(now);
            if pilot.tick(now, wall).contains(&Action::Sync) {
                gaps.push(t - last);
                last = t;
                pilot.on_sync_started();
                pilot.on_sync_finished(now, &SyncOutcome::Offline("hors ligne".into()));
            }
            t += Duration::from_secs(1);
        }
        assert_eq!(gaps, [Duration::ZERO, 2 * MINUTE, 5 * MINUTE, 15 * MINUTE]);

        // Refus d'identifiants : plus rien, même après une modification.
        let (now, _) = clock.at(t);
        pilot.on_sync_requested(now);
        pilot.on_sync_started();
        pilot.on_sync_finished(now, &SyncOutcome::Suspended("401".into()));
        pilot.on_modified(now);
        assert!(
            run(&mut pilot, &clock, t, t + 30 * MINUTE)
                .iter()
                .all(|(_, a)| *a != Action::Sync)
        );
        // Nouvelle saisie : échange immédiat.
        let (now, wall) = clock.at(t + 30 * MINUTE + Duration::from_secs(1));
        pilot.on_credentials_changed(now);
        assert_eq!(pilot.tick(now, wall), [Action::Sync]);
    }

    #[test]
    fn the_clipboard_is_cleared_after_its_delay_even_when_locked() {
        let clock = Clock::new();
        let mut pilot = Autopilot::new(5 * MINUTE, clock.start);
        pilot.on_unlocked(clock.start);
        pilot.on_sync_started();
        pilot.on_sync_finished(clock.start, &SyncOutcome::NotConfigured);
        let token = CopyToken(7);
        pilot.on_copied(token, clock.start, Duration::from_secs(30));
        pilot.on_locked();
        let seen = run(&mut pilot, &clock, Duration::ZERO, Duration::from_secs(40));
        assert_eq!(
            seen,
            [(Duration::from_secs(30), Action::ClearClipboard(token))]
        );
    }

    #[test]
    fn lock_messages() {
        assert_eq!(
            LockReason::Inactivity.message(5),
            "Coffre verrouillé après 5 minutes d'inactivité."
        );
        assert_eq!(
            LockReason::Inactivity.message(1),
            "Coffre verrouillé après 1 minute d'inactivité."
        );
    }
}
