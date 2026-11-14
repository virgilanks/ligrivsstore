// Messages entre les pages de l'extension (fenêtre, options) et le service
// worker, seul à parler à l'application.

import type { SiteEntry } from "./protocol";

/** Demandes des pages au service worker. */
export type PageRequest =
  | { kind: "etat" }
  | { kind: "entrees"; tabId: number }
  | { kind: "montrer-application" }
  | { kind: "oublier" };

/** Réponse simple. */
export type SimpleAnswer = { ok: true } | { ok: false; code: string; message: string };

/** État de l'appairage, pour les pages. */
export interface PairingStatus {
  paired: boolean;
  fingerprint: string | null;
  paired_at: string | null;
}

/** Réponse à « entrées » : l'adresse de la page vient de l'onglet. */
export type EntriesAnswer =
  | { ok: true; host: string; entries: SiteEntry[] }
  | { ok: false; code: string; message: string };

/** Messages du port « appairage » (page d'options ↔ service worker). */
export type PairingPortMessage =
  | { kind: "empreinte"; fingerprint: string }
  | { kind: "issue"; state: "confirmed" | "refused" | "expired"; fingerprint: string }
  | { kind: "enregistre" }
  | { kind: "erreur"; code: string; message: string };

/** Messages de la page d'options : comparaison des empreintes, et signal
 * de vie pendant l'attente (le service worker reste éveillé). */
export type PairingPortAnswer =
  | { kind: "empreintes-identiques"; same: boolean }
  | { kind: "veille" };

export const PAIRING_PORT = "appairage";
