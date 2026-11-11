// Messages échangés avec le cœur Rust (crates/app/src/dto.rs).

export interface Status {
  unlocked: boolean;
  vaultPath: string | null;
  keyfilePath: string | null;
  vaultName: string | null;
  entryCount: number;
  unsaved: boolean;
}

export interface DefaultPaths {
  vault: string;
  keyfile: string;
}

export type KeyfileChoice =
  | { kind: "none" }
  | { kind: "existing"; path: string }
  | { kind: "generate"; path: string };

export interface CreateVaultRequest {
  path: string;
  name: string;
  passphrase: string;
  keyfile: KeyfileChoice;
}

export interface OpenVaultRequest {
  path: string;
  passphrase: string;
  keyfilePath: string | null;
}

export interface EntryRow {
  id: string;
  title: string;
  username: string;
  url: string;
}

export interface EntryView extends EntryRow {
  notes: string;
  hasPassword: boolean;
  modified: string | null;
  historyLen: number;
}

export interface SaveEntryRequest {
  id: string | null;
  title: string;
  url: string;
  username: string;
  password: string | null;
  notes: string;
}

export interface GeneratorOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
}

export interface Generated {
  password: string;
  entropyBits: number;
}

export interface Strength {
  score: number;
  label: string;
  acceptable: boolean;
  guessesLog10: number;
  tooShort: boolean;
}
