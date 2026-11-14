//! Application ligrivsstore pour Windows : coquille Tauri.
//!
//! Chaque commande relaie l'interface vers la [`Session`] du paquet
//! `ligrivsstore-app`, dans une tâche à part : l'ouverture et
//! l'enregistrement d'un coffre (Argon2id) ne figent jamais la fenêtre.
//!
//! Un fil « pilote » interroge chaque seconde l'[`Autopilot`] et exécute ce
//! qu'il demande : verrouillage (inactivité, session Windows verrouillée,
//! mise en veille), synchronisation, effacement du presse-papiers.
//!
//! L'application ouvre aussi le canal nommé où le relais `ligrivsstore-pont`
//! la rejoint pour l'extension de navigateur (liaison chiffrée, appairage),
//! et vit dans la zone de notification : fermer la fenêtre la cache, le menu
//! de l'icône la quitte. Lancée avec `--arriere-plan` (par le relais, ou au
//! démarrage de Windows), elle démarre cachée.

// Pas de console sous Windows dans les versions distribuées.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use ligrivsstore_app::dto::{
    Activity, BackupView, BrowserView, CopyField, CreateVaultRequest, DefaultPaths, EntryRow,
    EntryView, Generated, GeneratorOptions, InstallRequest, OpenVaultRequest, PairingRequestView,
    PassphraseOptions, Preferences, RestoreView, SaveEntryRequest, Status, Strength,
    SyncSettingsRequest, SyncSettingsView,
};
use ligrivsstore_app::liaison::{self, Backend, Link};
use ligrivsstore_app::navigateurs::Browsers;
use ligrivsstore_app::{Action, AppError, Autopilot, LockReason, Monitor, Session};
use ligrivsstore_protocol::SiteEntry;
use ligrivsstore_win::canal::ChannelName;
use ligrivsstore_win::{SystemEvent, clipboard};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_autostart::ManagerExt;

/// Argument de démarrage caché, dans la zone de notification.
const BACKGROUND_ARGUMENT: &str = "--arriere-plan";

/// État partagé entre les commandes et le pilote.
struct AppState {
    session: Arc<Mutex<Session>>,
    pilot: Arc<Mutex<Autopilot>>,
    monitor: Arc<Monitor>,
    browsers: Arc<Browsers>,
}

/// Montre la fenêtre principale, au premier plan.
fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Ce que la liaison avec l'extension demande à l'application.
struct ShellBackend {
    session: Arc<Mutex<Session>>,
    monitor: Arc<Monitor>,
    app: AppHandle,
}

impl Backend for ShellBackend {
    fn is_unlocked(&self) -> bool {
        self.monitor.is_unlocked()
    }

    fn site_entries(&self, page_url: &str) -> Result<Vec<SiteEntry>, AppError> {
        guard(&self.session).site_entries(page_url)
    }

    fn show(&self) {
        show_main(&self.app);
    }

    fn pairing_requested(&self) {
        show_main(&self.app);
    }
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
    let mut activity = state.monitor.activity();
    activity.pairing_requests = state.browsers.pending_count();
    activity
}

/// Navigateurs appairés.
#[tauri::command]
fn list_browsers(state: State<'_, AppState>) -> Vec<BrowserView> {
    state.browsers.list()
}

/// Demandes d'appairage en attente de décision.
#[tauri::command]
fn pending_pairings(state: State<'_, AppState>) -> Vec<PairingRequestView> {
    state.browsers.pending()
}

/// Confirme ou refuse une demande d'appairage.
#[tauri::command]
fn decide_pairing(state: State<'_, AppState>, id: String, confirm: bool) -> Result<(), AppError> {
    guard(&state.pilot).on_activity(Instant::now());
    state.browsers.decide(&id, confirm)
}

/// Révoque un navigateur appairé.
#[tauri::command]
fn revoke_browser(state: State<'_, AppState>, id: String) -> Result<(), AppError> {
    guard(&state.pilot).on_activity(Instant::now());
    state.browsers.revoke(&id)
}

/// Démarrage avec Windows (caché, dans la zone de notification).
#[tauri::command]
fn get_autostart(app: AppHandle) -> Result<bool, AppError> {
    app.autolaunch()
        .is_enabled()
        .map_err(|e| AppError::new("demarrage", e.to_string()))
}

/// Active ou retire le démarrage avec Windows ; renvoie l'état obtenu.
#[tauri::command]
fn set_autostart(app: AppHandle, enabled: bool) -> Result<bool, AppError> {
    let launcher = app.autolaunch();
    let outcome = if enabled {
        launcher.enable()
    } else {
        launcher.disable()
    };
    outcome.map_err(|e| AppError::new("demarrage", e.to_string()))?;
    launcher
        .is_enabled()
        .map_err(|e| AppError::new("demarrage", e.to_string()))
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

/// Ouvre la liaison avec l'extension : clé de l'application, registre des
/// navigateurs, canal nommé du compte.
fn start_link(
    config_dir: &std::path::Path,
    browsers: &Arc<Browsers>,
    backend: Arc<dyn Backend>,
) -> Result<(), AppError> {
    let (identity, renewed) = liaison::load_identity(config_dir)?;
    if renewed {
        // Clé illisible, remplacée : les anciens appairages ne servent plus.
        browsers.forget_all()?;
    }
    let name = ChannelName::for_current_user().map_err(AppError::internal)?;
    let link = Link::new(identity, Arc::clone(browsers), backend);
    liaison::spawn_server(&name, Arc::new(link))
}

/// Déclare le relais auprès de Chrome et d'Edge pour l'utilisateur courant,
/// si le manifeste installé avec l'application est là (pas en développement).
#[cfg(windows)]
fn register_native_host(app: &AppHandle) -> Result<(), String> {
    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;
    let manifest = app
        .path()
        .resource_dir()
        .map_err(|e| e.to_string())?
        .join(format!("{}.json", ligrivsstore_protocol::HOST_NAME));
    if !manifest.is_file() {
        return Err(format!("manifeste absent : {}", manifest.display()));
    }
    let manifest = manifest.display().to_string();
    let user = RegKey::predef(HKEY_CURRENT_USER);
    for browser in [r"Software\Google\Chrome", r"Software\Microsoft\Edge"] {
        let path = format!(
            r"{browser}\NativeMessagingHosts\{}",
            ligrivsstore_protocol::HOST_NAME
        );
        let (key, _) = user.create_subkey(&path).map_err(|e| e.to_string())?;
        let current: Option<String> = key.get_value("").ok();
        if current.as_deref() != Some(manifest.as_str()) {
            key.set_value("", &manifest).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Icône de la zone de notification : ouvrir, verrouiller, quitter.
fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "ouvrir", "Ouvrir ligrivsstore", true, None::<&str>)?;
    let lock = MenuItem::with_id(
        app,
        "verrouiller",
        "Verrouiller le coffre",
        true,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(app, "quitter", "Quitter", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &lock, &quit])?;
    let mut builder = TrayIconBuilder::with_id("principale")
        .tooltip("ligrivsstore")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "ouvrir" => show_main(app),
            "verrouiller" => lock_from_tray(app),
            "quitter" => {
                lock_from_tray(app);
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

fn lock_from_tray(app: &AppHandle) {
    let state = app.state::<AppState>();
    guard(&state.session).lock(LockReason::Manual);
    guard(&state.pilot).on_locked();
}

fn main() {
    let outcome = tauri::Builder::default()
        // Une seule instance : un second lancement ramène la fenêtre existante.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_main(app);
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec![BACKGROUND_ARGUMENT]),
        ))
        // Fermer la fenêtre la cache : l'application reste dans la zone de
        // notification pour l'extension. « Quitter » est dans son menu.
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
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

            let browsers = Arc::new(Browsers::load(&config_dir));
            let backend = Arc::new(ShellBackend {
                session: Arc::clone(&session),
                monitor: Arc::clone(&monitor),
                app: app.handle().clone(),
            });
            if let Err(error) = start_link(&config_dir, &browsers, backend) {
                eprintln!("liaison avec les navigateurs indisponible : {error}");
            }
            #[cfg(windows)]
            if let Err(error) = register_native_host(app.handle()) {
                eprintln!("relais non déclaré aux navigateurs : {error}");
            }

            app.manage(AppState {
                session,
                pilot,
                monitor,
                browsers,
            });
            build_tray(app)?;
            if !std::env::args().any(|arg| arg == BACKGROUND_ARGUMENT) {
                show_main(app.handle());
            }
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
            list_browsers,
            pending_pairings,
            decide_pairing,
            revoke_browser,
            get_autostart,
            set_autostart,
        ])
        .run(tauri::generate_context!());
    if let Err(error) = outcome {
        eprintln!("ligrivsstore n'a pas pu démarrer : {error}");
        std::process::exit(1);
    }
}
