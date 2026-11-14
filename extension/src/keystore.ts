// Clés et appairage de l'extension, dans IndexedDB : seul endroit où le
// navigateur garde une clé privée non exportable (objet CryptoKey). Rien
// d'autre n'est conservé : ni mot de passe, ni liste d'entrées.

import type { KeyPairRaw } from "./protocol";

const DATABASE = "ligrivsstore";
const STORE = "appairage";
const KEY_ID = "extension";
const PAIRING_ID = "application";

/** Appairage confirmé des deux côtés. */
export interface Pairing {
  /** Clé publique permanente de l'application (32 octets). */
  appPublic: Uint8Array<ArrayBuffer>;
  /** Empreinte comparée à l'appairage. */
  fingerprint: string;
  /** Date de l'appairage (ISO 8601). */
  paired: string;
}

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB indisponible"));
  });
}

async function run<T>(mode: IDBTransactionMode, action: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await open();
  try {
    return await new Promise<T>((resolve, reject) => {
      const transaction = db.transaction(STORE, mode);
      const request = action(transaction.objectStore(STORE));
      transaction.oncomplete = () => resolve(request.result);
      transaction.onerror = () => reject(transaction.error ?? new Error("IndexedDB : échec"));
      transaction.onabort = () => reject(transaction.error ?? new Error("IndexedDB : abandon"));
    });
  } finally {
    db.close();
  }
}

/** Clé permanente de l'extension, si elle existe. */
export async function loadKeyPair(): Promise<KeyPairRaw | null> {
  const stored = (await run("readonly", (s) => s.get(KEY_ID))) as KeyPairRaw | undefined;
  return stored ?? null;
}

export async function saveKeyPair(pair: KeyPairRaw): Promise<void> {
  await run("readwrite", (s) => s.put(pair, KEY_ID));
}

export async function loadPairing(): Promise<Pairing | null> {
  const stored = (await run("readonly", (s) => s.get(PAIRING_ID))) as Pairing | undefined;
  return stored ?? null;
}

export async function savePairing(pairing: Pairing): Promise<void> {
  await run("readwrite", (s) => s.put(pairing, PAIRING_ID));
}

/** Oublie l'appairage et la clé : un nouvel appairage tirera une autre clé. */
export async function forgetAll(): Promise<void> {
  await run("readwrite", (s) => s.clear());
}
