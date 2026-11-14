// Appels au cœur Rust. Chaque fonction correspond à une commande déclarée
// dans src-tauri/src/main.rs et autorisée dans src-tauri/capabilities.

import { invoke } from "@tauri-apps/api/core";
import type {
  Activity,
  BackupView,
  BrowserView,
  CopyField,
  CreateVaultRequest,
  DefaultPaths,
  EntryRow,
  EntryView,
  Generated,
  GeneratorOptions,
  InstallRequest,
  OpenVaultRequest,
  PairingRequestView,
  PassphraseOptions,
  Preferences,
  RestoreView,
  SaveEntryRequest,
  Status,
  Strength,
  SyncSettingsRequest,
  SyncSettingsView,
} from "./types";

/** Erreur renvoyée par le cœur : code stable et message en français. */
export class AppError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

function toAppError(raw: unknown): AppError {
  if (raw instanceof AppError) return raw;
  if (raw && typeof raw === "object" && "code" in raw && "message" in raw) {
    const { code, message } = raw as { code: unknown; message: unknown };
    return new AppError(String(code), String(message));
  }
  return new AppError("interne", typeof raw === "string" ? raw : "erreur inattendue");
}

/** Message à afficher pour une erreur quelconque. */
export function messageOf(error: unknown): string {
  return toAppError(error).message;
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (raw) {
    throw toAppError(raw);
  }
}

export const api = {
  status: () => call<Status>("status"),
  activity: () => call<Activity>("activity"),
  pingActivity: () => call<void>("ping_activity"),
  defaultPaths: () => call<DefaultPaths>("default_paths"),
  createVault: (request: CreateVaultRequest) => call<Status>("create_vault", { request }),
  openVault: (request: OpenVaultRequest) => call<Status>("open_vault", { request }),
  installFromServer: (request: InstallRequest) => call<Status>("install_from_server", { request }),
  lockVault: () => call<Status>("lock_vault"),
  forgetVault: () => call<Status>("forget_vault"),
  listEntries: (query: string) => call<EntryRow[]>("list_entries", { query }),
  getEntry: (id: string) => call<EntryView>("get_entry", { id }),
  revealPassword: (id: string) => call<string>("reveal_password", { id }),
  /** Copie par le cœur ; renvoie le délai d'effacement, en secondes. */
  copyField: (id: string, field: CopyField) => call<number>("copy_field", { id, field }),
  saveEntry: (request: SaveEntryRequest) => call<string>("save_entry", { request }),
  deleteEntry: (id: string) => call<void>("delete_entry", { id }),
  retrySave: () => call<void>("retry_save"),
  getSyncSettings: () => call<SyncSettingsView>("get_sync_settings"),
  configureSync: (request: SyncSettingsRequest) =>
    call<SyncSettingsView>("configure_sync", { request }),
  syncNow: () => call<void>("sync_now"),
  listBackups: () => call<BackupView[]>("list_backups"),
  restoreBackup: (id: string) => call<RestoreView>("restore_backup", { id }),
  getPreferences: () => call<Preferences>("get_preferences"),
  savePreferences: (preferences: Preferences) =>
    call<Preferences>("save_preferences", { preferences }),
  generatePassword: (options: GeneratorOptions) =>
    call<Generated>("generate_password", { options }),
  generatePassphrase: (options: PassphraseOptions) =>
    call<Generated>("generate_passphrase", { options }),
  passphraseStrength: (passphrase: string) =>
    call<Strength>("passphrase_strength", { passphrase }),
  listBrowsers: () => call<BrowserView[]>("list_browsers"),
  pendingPairings: () => call<PairingRequestView[]>("pending_pairings"),
  decidePairing: (id: string, confirm: boolean) => call<void>("decide_pairing", { id, confirm }),
  revokeBrowser: (id: string) => call<void>("revoke_browser", { id }),
  getAutostart: () => call<boolean>("get_autostart"),
  /** Renvoie l'état obtenu. */
  setAutostart: (enabled: boolean) => call<boolean>("set_autostart", { enabled }),
};
