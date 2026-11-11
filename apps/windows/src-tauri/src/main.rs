//! Application ligrivsstore pour Windows : coquille Tauri.
//!
//! Chaque commande relaie l'interface vers la [`Session`] du paquet
//! `ligrivsstore-app`, dans une tâche à part : l'ouverture et
//! l'enregistrement d'un coffre (Argon2id) ne figent jamais la fenêtre.

// Pas de console sous Windows dans les versions distribuées.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ligrivsstore_app::dto::{
    CreateVaultRequest, DefaultPaths, EntryRow, EntryView, Generated, GeneratorOptions,
    OpenVaultRequest, SaveEntryRequest, Status, Strength,
};
use ligrivsstore_app::{AppError, Session};
use tauri::{Manager, State};

/// Session partagée entre les commandes.
struct AppState(Arc<Mutex<Session>>);

/// Exécute `job` sur la session, hors du fil de l'interface.
async fn with_session<T, F>(state: State<'_, AppState>, job: F) -> Result<T, AppError>
where
    T: Send + 'static,
    F: FnOnce(&mut Session) -> Result<T, AppError> + Send + 'static,
{
    let session = Arc::clone(&state.0);
    tauri::async_runtime::spawn_blocking(move || {
        let mut guard = session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        job(&mut guard)
    })
    .await
    .map_err(AppError::internal)?
}

#[tauri::command]
async fn status(state: State<'_, AppState>) -> Result<Status, AppError> {
    with_session(state, |s| Ok(s.status())).await
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
    with_session(state, move |s| s.create_vault(request)).await
}

#[tauri::command]
async fn open_vault(
    state: State<'_, AppState>,
    request: OpenVaultRequest,
) -> Result<Status, AppError> {
    with_session(state, move |s| s.open_vault(request)).await
}

#[tauri::command]
async fn lock_vault(state: State<'_, AppState>) -> Result<Status, AppError> {
    with_session(state, |s| Ok(s.lock())).await
}

#[tauri::command]
async fn forget_vault(state: State<'_, AppState>) -> Result<Status, AppError> {
    with_session(state, Session::forget_vault).await
}

#[tauri::command]
async fn list_entries(
    state: State<'_, AppState>,
    query: String,
) -> Result<Vec<EntryRow>, AppError> {
    with_session(state, move |s| s.list_entries(&query)).await
}

#[tauri::command]
async fn get_entry(state: State<'_, AppState>, id: String) -> Result<EntryView, AppError> {
    with_session(state, move |s| s.entry(&id)).await
}

#[tauri::command]
async fn reveal_password(state: State<'_, AppState>, id: String) -> Result<String, AppError> {
    let password = with_session(state, move |s| s.reveal_password(&id)).await?;
    Ok(password.as_str().to_owned())
}

#[tauri::command]
async fn save_entry(
    state: State<'_, AppState>,
    request: SaveEntryRequest,
) -> Result<String, AppError> {
    with_session(state, move |s| s.save_entry(request)).await
}

#[tauri::command]
async fn delete_entry(state: State<'_, AppState>, id: String) -> Result<(), AppError> {
    with_session(state, move |s| s.delete_entry(&id)).await
}

#[tauri::command]
async fn retry_save(state: State<'_, AppState>) -> Result<(), AppError> {
    with_session(state, Session::retry_save).await
}

#[tauri::command]
fn generate_password(options: GeneratorOptions) -> Result<Generated, AppError> {
    ligrivsstore_app::generate_password(&options)
}

#[tauri::command]
fn passphrase_strength(passphrase: String) -> Strength {
    let passphrase = zeroize::Zeroizing::new(passphrase);
    ligrivsstore_app::passphrase_strength(&passphrase)
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
            app.manage(AppState(Arc::new(Mutex::new(Session::load(&config_dir)))));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            status,
            default_paths,
            create_vault,
            open_vault,
            lock_vault,
            forget_vault,
            list_entries,
            get_entry,
            reveal_password,
            save_entry,
            delete_entry,
            retry_save,
            generate_password,
            passphrase_strength,
        ])
        .run(tauri::generate_context!());
    if let Err(error) = outcome {
        eprintln!("ligrivsstore n'a pas pu démarrer : {error}");
        std::process::exit(1);
    }
}
