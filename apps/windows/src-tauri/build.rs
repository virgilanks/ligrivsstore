//! Génère le contexte de Tauri et les permissions des commandes de
//! l'application : seules les commandes listées ici existent pour l'interface.

const COMMANDS: &[&str] = &[
    "status",
    "default_paths",
    "create_vault",
    "open_vault",
    "lock_vault",
    "forget_vault",
    "list_entries",
    "get_entry",
    "reveal_password",
    "save_entry",
    "delete_entry",
    "retry_save",
    "generate_password",
    "passphrase_strength",
];

fn main() {
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS));
    if let Err(error) = tauri_build::try_build(attributes) {
        eprintln!("échec de la préparation de Tauri : {error:#}");
        std::process::exit(1);
    }
}
