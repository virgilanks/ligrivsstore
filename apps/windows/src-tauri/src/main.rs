//! Application ligrivsstore pour Windows : coquille Tauri.
//!
//! Chaque commande relaie l'interface vers la [`Session`] du paquet
//! `ligrivsstore-app`, dans une tâche à part : l'ouverture et
//! l'enregistrement d'un coffre (Argon2id) ne figent jamais la fenêtre.
//!
//! Un fil « pilote » interroge chaque seconde l'[`Autopilot`] et exécute ce
//! qu'il demande : verrouillage (inactivité, session Windows verrouillée,
//! mise en veille), synchronisation, effacement du presse-papiers.

// Pas de console sous Windows dans les versions distribuées.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use ligrivsstore_app::dto::{
    Activity, BackupView, CopyField, CreateVaultRequest, DefaultPaths, EntryRow, EntryView,
    Generated, GeneratorOptions, InstallRequest, OpenVaultRequest, PassphraseOptions, Preferences,
    RestoreView, SaveEntryRequest, Status, Strength, SyncSettingsRequest, SyncSettingsView,
};
use ligrivsstore_app::{Action, AppError, Autopilot, LockReason, Monitor, Session};
use ligrivsstore_win::{SystemEvent, clipboard};
use tauri::{Manager, State};

/// État partagé entre les commandes et le pilote.
struct AppState {
    session: Arc<Mutex<Session>>,
    pilot: Arc<Mutex<Autopilot>>,
    monitor: Arc<Monitor>,
}

/// Verrou, même si un fil a paniqué en le tenant : l'état reste cohérent
/// (chaque opération de la session est complète ou sans effet).
fn guard<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Ce qu'une commande signale au pilote après coup.
#[derive(Clone, Copy)]
enum Effect {
    /// Simple consultation : activité de l'utilisateur.
    None,
    /// Coffre ouvert.
    Unlocked,
    /// Coffre modifié.
    Modified,
}

/// Exécute `job` sur la session, hors du fil de l'interface, puis informe le
/// pilote. Toute commande compte comme une activité de l'utilisateur.
async fn with_session<T, F>(
    state: State<'_, AppState>,
    effect: Effect,
    job: F,
) -> Result<T, AppError>
where
    T: Send + 'static,
    F: FnOnce(&mut Session) -> Result<T, AppError> + Send + 'static,
{
    let session = Arc::clone(&state.session);
    let pilot = Arc::clone(&state.pilot);
    tauri::async_runtime::spawn_blocking(move || {
        let result = job(&mut guard(&session));
        let now = Instant::now();
        let mut pilot = guard(&pilot);
        pilot.on_activity(now);
        if result.is_ok() {
            match effect {
                Effect::None => {}
                Effect::Unlocked => pilot.on_unlocked(now),
                Effect::Modified => pilot.on_modified(now),
            }
        }
        result
    })
    .await
    .map_err(AppError::internal)?
}

#[tauri::command]
async fn status(state: State<'_, AppState>) -> Result<Status, AppError> {
    with_session(state, Effect::None, |s| Ok(s.status())).await
}

/// État observable, relu régulièrement par l'interface : ne compte pas comme
/// une activité et n'attend jamais la session.
#[tauri::command]
fn activity(state: State<'_, AppState>) -> Activity {
    state.monitor.activity()
}

/// Activité de l'utilisateur dans la fenêtre (frappe, clic), qui repousse le
/// verrouillage automatique.
#[tauri::command]
fn ping_activity(state: State<'_, AppState>) {
    guard(&state.pilot).on_activity(Instant::now());
}

#[tauri::command]
fn default_paths(app: tauri::AppHandle) -> Result<DefaultPaths, AppError> {
    let path = app.path();
    let documents = path.document_dir().map_err(AppError::internal)?;
    // Fichier clé : dans les données locales de l'utilisateur, que OneDrive
    // ne synchronise pas (il ne rejoint donc jamais le coffre), mais hors du
    // dossier de l'application : la désinstallation efface ce dernier quand
    // on coche « Supprimer les données de l'application ».
    let local = path.local_data_dir().map_err(AppError::internal)?;
    let text = |p: PathBuf| p.display().to_string();
    Ok(DefaultPaths {
        vault: text(documents.join("ligrivsstore").join("coffre.kdbx")),
        keyfile: text(local.join("ligrivsstore-cles").join("coffre.keyx")),
    })
}

#[tauri::command]
async fn create_vault(
    state: State<'_, AppState>,
    request: CreateVaultRequest,
) -> Result<Status, AppError> {
    with_session(state, Effect::Unlocked, move |s| s.create_vault(request)).await
}

#[tauri::command]
async fn open_vault(
    state: State<'_, AppState>,
    request: OpenVaultRequest,
) -> Result<Status, AppError> {
    with_session(state, Effect::Unlocked, move |s| s.open_vault(request)).await
}

#[tauri::command]
async fn install_from_server(
    state: State<'_, AppState>,
    request: InstallRequest,
) -> Result<Status, AppError> {
    with_session(state, Effect::Unlocked, move |s| {
        s.install_from_server(request)
    })
    .await
}

#[tauri::command]
async fn lock_vault(state: State<'_, AppState>) -> Result<Status, AppError> {
    let pilot = Arc::clone(&state.pilot);
    let status = with_session(state, Effect::None, |s| Ok(s.lock(LockReason::Manual))).await?;
    guard(&pilot).on_locked();
    Ok(status)
}

#[tauri::command]
async fn forget_vault(state: State<'_, AppState>) -> Result<Status, AppError> {
    with_session(state, Effect::None, Session::forget_vault).await
}

#[tauri::command]
async fn list_entries(
    state: State<'_, AppState>,
    query: String,
) -> Result<Vec<EntryRow>, AppError> {
    with_session(state, Effect::None, move |s| s.list_entries(&query)).await
}

#[tauri::command]
async fn get_entry(state: State<'_, AppState>, id: String) -> Result<EntryView, AppError> {
    with_session(state, Effect::None, move |s| s.entry(&id)).await
}

#[tauri::command]
async fn reveal_password(state: State<'_, AppState>, id: String) -> Result<String, AppError> {
    let password = with_session(state, Effect::None, move |s| s.reveal_password(&id)).await?;
    Ok(password.as_str().to_owned())
}

/// Copie un identifiant ou un mot de passe par le cœur de l'application, hors
/// de l'historique du presse-papiers et du cloud ; renvoie le délai
/// d'effacement, en secondes.
#[tauri::command]
async fn copy_field(
    state: State<'_, AppState>,
    id: String,
    field: CopyField,
) -> Result<u32, AppError> {
    let pilot = Arc::clone(&state.pilot);
    let (secret, seconds) = with_session(state, Effect::None, move |s| {
        Ok((
            s.secret_for_copy(&id, field)?,
            s.preferences().clipboard_seconds,
        ))
    })
    .await?;
    let token = tauri::async_runtime::spawn_blocking(move || clipboard::copy_protected(&secret))
        .await
        .map_err(AppError::internal)?
        .map_err(|e| AppError::new("presse_papiers", e.to_string()))?;
    guard(&pilot).on_copied(
        token,
        Instant::now(),
        Duration::from_secs(u64::from(seconds)),
    );
    Ok(seconds)
}

#[tauri::command]
async fn save_entry(
    state: State<'_, AppState>,
    request: SaveEntryRequest,
) -> Result<String, AppError> {
    with_session(state, Effect::Modified, move |s| s.save_entry(request)).await
}

#[tauri::command]
async fn delete_entry(state: State<'_, AppState>, id: String) -> Result<(), AppError> {
    with_session(state, Effect::Modified, move |s| s.delete_entry(&id)).await
}

#[tauri::command]
async fn retry_save(state: State<'_, AppState>) -> Result<(), AppError> {
    with_session(state, Effect::Modified, Session::retry_save).await
}

#[tauri::command]
async fn get_sync_settings(state: State<'_, AppState>) -> Result<SyncSettingsView, AppError> {
    with_session(state, Effect::None, |s| s.sync_settings()).await
}

#[tauri::command]
async fn configure_sync(
    state: State<'_, AppState>,
    request: SyncSettingsRequest,
) -> Result<SyncSettingsView, AppError> {
    let pilot = Arc::clone(&state.pilot);
    let (view, _changed) =
        with_session(state, Effect::None, move |s| s.configure_sync(request)).await?;
    // Réglage enregistré : un échange tout de suite, suspension levée.
    guard(&pilot).on_credentials_changed(Instant::now());
    Ok(view)
}

/// Demande une synchronisation : le pilote la lance dans la seconde ;
/// l'interface en suit l'état par `activity`.
#[tauri::command]
fn sync_now(state: State<'_, AppState>) {
    guard(&state.pilot).on_sync_requested(Instant::now());
}

#[tauri::command]
async fn list_backups(state: State<'_, AppState>) -> Result<Vec<BackupView>, AppError> {
    with_session(state, Effect::None, |s| s.backups()).await
}

#[tauri::command]
async fn restore_backup(state: State<'_, AppState>, id: String) -> Result<RestoreView, AppError> {
    with_session(state, Effect::Modified, move |s| s.restore_backup(&id)).await
}

#[tauri::command]
async fn get_preferences(state: State<'_, AppState>) -> Result<Preferences, AppError> {
    with_session(state, Effect::None, |s| Ok(s.preferences())).await
}

#[tauri::command]
async fn save_preferences(
    state: State<'_, AppState>,
    preferences: Preferences,
) -> Result<Preferences, AppError> {
    let pilot = Arc::clone(&state.pilot);
    let saved = with_session(state, Effect::None, move |s| s.set_preferences(preferences)).await?;
    guard(&pilot).set_lock_after(lock_delay(saved.lock_minutes));
    Ok(saved)
}

#[tauri::command]
fn generate_password(options: GeneratorOptions) -> Result<Generated, AppError> {
    ligrivsstore_app::generate_password(&options)
}

#[tauri::command]
fn generate_passphrase(options: PassphraseOptions) -> Result<Generated, AppError> {
    ligrivsstore_app::generate_passphrase(&options)
}

#[tauri::command]
fn passphrase_strength(passphrase: String) -> Strength {
    let passphrase = zeroize::Zeroizing::new(passphrase);
    ligrivsstore_app::passphrase_strength(&passphrase)
}

fn lock_delay(minutes: u32) -> Duration {
    Duration::from_secs(u64::from(minutes) * 60)
}

/// Fil pilote : événements du système et échéances, chaque seconde.
fn run_autopilot(
    session: Arc<Mutex<Session>>,
    pilot: Arc<Mutex<Autopilot>>,
    events: mpsc::Receiver<SystemEvent>,
) {
    let mut events = Some(events);
    loop {
        let event = match &events {
            Some(receiver) => match receiver.recv_timeout(Duration::from_secs(1)) {
                Ok(event) => Some(event),
                Err(RecvTimeoutError::Timeout) => None,
                Err(RecvTimeoutError::Disconnected) => {
                    events = None;
                    None
                }
            },
            None => {
                std::thread::sleep(Duration::from_secs(1));
                None
            }
        };
        let mut actions = Vec::new();
        {
            let mut pilot = guard(&pilot);
            if let Some(action) = event.and_then(|e| pilot.on_system_event(e)) {
                actions.push(action);
            }
            actions.extend(pilot.tick(Instant::now(), SystemTime::now()));
        }
        // Le pilote n'est jamais tenu pendant une opération de la session.
        for action in actions {
            match action {
                Action::Lock(reason) => {
                    guard(&session).lock(reason);
                    guard(&pilot).on_locked();
                }
                Action::Sync => {
                    let outcome = guard(&session).sync_now();
                    guard(&pilot).on_sync_finished(Instant::now(), &outcome);
                }
                Action::ClearClipboard(token) => {
                    let _ = clipboard::clear_if_unchanged(token);
                }
            }
        }
    }
}

fn main() {
    let outcome = tauri::Builder::default()
        // Une seule instance : un second lancement ramène la fenêtre existante.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let config_dir = app.path().app_config_dir()?;
            let session = Session::load(&config_dir);
            let monitor = session.monitor();
            let lock_after = lock_delay(session.preferences().lock_minutes);
            let session = Arc::new(Mutex::new(session));
            let pilot = Arc::new(Mutex::new(Autopilot::new(lock_after, Instant::now())));

            let (sender, events) = mpsc::channel();
            // Sans cette surveillance, le verrouillage à l'inactivité et au
            // réveil reste assuré par le pilote.
            if let Err(error) = ligrivsstore_win::watch_system_events(move |event| {
                let _ = sender.send(event);
            }) {
                eprintln!("surveillance de la session Windows indisponible : {error}");
            }
            let (s, p) = (Arc::clone(&session), Arc::clone(&pilot));
            std::thread::Builder::new()
                .name("ligrivsstore-pilote".into())
                .spawn(move || run_autopilot(s, p, events))?;

            app.manage(AppState {
                session,
                pilot,
                monitor,
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            status,
            activity,
            ping_activity,
            default_paths,
            create_vault,
            open_vault,
            install_from_server,
            lock_vault,
            forget_vault,
            list_entries,
            get_entry,
            reveal_password,
            copy_field,
            save_entry,
            delete_entry,
            retry_save,
            get_sync_settings,
            configure_sync,
            sync_now,
            list_backups,
            restore_backup,
            get_preferences,
            save_preferences,
            generate_password,
            generate_passphrase,
            passphrase_strength,
        ])
        .run(tauri::generate_context!());
    if let Err(error) = outcome {
        eprintln!("ligrivsstore n'a pas pu démarrer : {error}");
        std::process::exit(1);
    }
}
