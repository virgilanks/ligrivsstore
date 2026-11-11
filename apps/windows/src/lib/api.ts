// Appels au cœur Rust. Chaque fonction correspond à une commande déclarée
// dans src-tauri/src/main.rs et autorisée dans src-tauri/capabilities.

import { invoke } from "@tauri-apps/api/core";
import type {
  CreateVaultRequest,
  DefaultPaths,
  EntryRow,
  EntryView,
  Generated,
  GeneratorOptions,
  OpenVaultRequest,
  SaveEntryRequest,
  Status,
  Strength,
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
  defaultPaths: () => call<DefaultPaths>("default_paths"),
  createVault: (request: CreateVaultRequest) => call<Status>("create_vault", { request }),
  openVault: (request: OpenVaultRequest) => call<Status>("open_vault", { request }),
  lockVault: () => call<Status>("lock_vault"),
  forgetVault: () => call<Status>("forget_vault"),
  listEntries: (query: string) => call<EntryRow[]>("list_entries", { query }),
  getEntry: (id: string) => call<EntryView>("get_entry", { id }),
  revealPassword: (id: string) => call<string>("reveal_password", { id }),
  saveEntry: (request: SaveEntryRequest) => call<string>("save_entry", { request }),
  deleteEntry: (id: string) => call<void>("delete_entry", { id }),
  retrySave: () => call<void>("retry_save"),
  generatePassword: (options: GeneratorOptions) =>
    call<Generated>("generate_password", { options }),
  passphraseStrength: (passphrase: string) =>
    call<Strength>("passphrase_strength", { passphrase }),
};
