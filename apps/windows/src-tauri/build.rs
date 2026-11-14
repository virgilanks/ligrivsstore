//! Génère le contexte de Tauri et les permissions des commandes de
//! l'application : seules les commandes listées ici existent pour l'interface.

const COMMANDS: &[&str] = &[
    "status",
    "activity",
    "ping_activity",
    "default_paths",
    "create_vault",
    "open_vault",
    "install_from_server",
    "lock_vault",
    "forget_vault",
    "list_entries",
    "get_entry",
    "reveal_password",
    "copy_field",
    "save_entry",
    "delete_entry",
    "retry_save",
    "get_sync_settings",
    "configure_sync",
    "sync_now",
    "list_backups",
    "restore_backup",
    "get_preferences",
    "save_preferences",
    "generate_password",
    "generate_passphrase",
    "passphrase_strength",
    "list_browsers",
    "pending_pairings",
    "decide_pairing",
    "revoke_browser",
    "get_autostart",
    "set_autostart",
];

fn main() {
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS));
    if let Err(error) = tauri_build::try_build(attributes) {
        eprintln!("échec de la préparation de Tauri : {error:#}");
        std::process::exit(1);
    }
}
