// Protocole entre l'extension et l'application ligrivsstore, avec l'API Web
// Crypto du navigateur (X25519 depuis Chrome et Edge 133). C'est la même
// construction que le paquet Rust ligrivsstore-protocol (crates/protocol) ;
// les vecteurs d'essai communs le vérifient (tests/protocole.test.ts).
//
// - Empreinte d'appairage : SHA-256(libellé, clé de l'application, clé de
//   l'extension), lue en six groupes de cinq chiffres.
// - Session : HKDF-SHA256 sur les échanges permanent-permanent et
//   éphémère-éphémère, liés aux quatre clés publiques ; AES-256-GCM, une clé
//   par sens ; nonce = sens et compteur ; le compteur reçu doit être
//   exactement le suivant.

export const VERSION = 1;
export const HOST_NAME = "com.ligrivs.ligrivsstore";

const encoder = new TextEncoder();
const FINGERPRINT_LABEL = encoder.encode("ligrivsstore/empreinte/v1");
const HKDF_SALT = encoder.encode("ligrivsstore/protocole/v1");
const HKDF_INFO = encoder.encode("ligrivsstore/session/v1");
const AAD = encoder.encode("ligrivsstore/v1");
const CLIENT_TO_APP = 1;
const APP_TO_CLIENT = 2;
/** Messages par sens et par session ; au-delà, rouvrir la liaison. */
export const MAX_MESSAGES = 2 ** 32;

/** Erreur du protocole, avec un code stable. */
export class ProtocolError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export function toBase64(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text);
}

export function fromBase64(text: string): Uint8Array<ArrayBuffer> {
  let binary: string;
  try {
    binary = atob(text);
  } catch {
    throw new ProtocolError("message_invalide", "Base64 illisible");
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Clé publique X25519 de 32 octets. */
export function checkKey(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  if (bytes.length !== 32) {
    throw new ProtocolError("cle_refusee", "clé de taille inattendue");
  }
  return Uint8Array.from(bytes);
}

/** Paire de clés X25519 : la clé privée n'est jamais exportable. */
export interface KeyPairRaw {
  privateKey: CryptoKey;
  publicRaw: Uint8Array<ArrayBuffer>;
}

export async function generateKeyPair(): Promise<KeyPairRaw> {
  const pair = (await crypto.subtle.generateKey({ name: "X25519" }, false, [
    "deriveBits",
  ])) as CryptoKeyPair;
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return { privateKey: pair.privateKey, publicRaw };
}

async function importPublic(raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", checkKey(raw), { name: "X25519" }, true, []);
}

async function dh(privateKey: CryptoKey, peer: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  try {
    // Le navigateur refuse un résultat nul (clé d'ordre faible).
    const bits = await crypto.subtle.deriveBits(
      { name: "X25519", public: await importPublic(peer) },
      privateKey,
      256,
    );
    return new Uint8Array(bits);
  } catch {
    throw new ProtocolError("cle_refusee", "échange de clés refusé");
  }
}

/** Empreinte d'appairage : six groupes de cinq chiffres. */
export async function fingerprint(appPublic: Uint8Array, clientPublic: Uint8Array): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      concat(FINGERPRINT_LABEL, checkKey(appPublic), checkKey(clientPublic)),
    ),
  );
  const groups: string[] = [];
  for (let group = 0; group < 6; group += 1) {
    let value = 0;
    for (let i = 0; i < 5; i += 1) value = value * 256 + (digest[group * 5 + i] ?? 0);
    groups.push(String(value % 100_000).padStart(5, "0"));
  }
  return groups.join(" ");
}

function nonce(direction: number, counter: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(12);
  bytes[3] = direction;
  new DataView(bytes.buffer).setBigUint64(4, BigInt(counter));
  return bytes;
}

/** Côté de la liaison. */
export type Role = "extension" | "application";

/** Session chiffrée : une clé et un compteur par sens. */
export class Session {
  private sent = 0;
  private received = 0;

  private constructor(
    private readonly sendKey: CryptoKey,
    private readonly receiveKey: CryptoKey,
    private readonly sendDirection: number,
    private readonly receiveDirection: number,
  ) {}

  /** Établit la session à partir des clés permanentes et éphémères. */
  static async establish(
    role: Role,
    ownStatic: KeyPairRaw,
    ownEphemeral: KeyPairRaw,
    peerStatic: Uint8Array<ArrayBuffer>,
    peerEphemeral: Uint8Array<ArrayBuffer>,
  ): Promise<Session> {
    const staticShared = await dh(ownStatic.privateKey, peerStatic);
    const ephemeralShared = await dh(ownEphemeral.privateKey, peerEphemeral);
    const [clientStatic, appStatic, clientEph, appEph] =
      role === "extension"
        ? [ownStatic.publicRaw, peerStatic, ownEphemeral.publicRaw, peerEphemeral]
        : [peerStatic, ownStatic.publicRaw, peerEphemeral, ownEphemeral.publicRaw];
    const ikm = await crypto.subtle.importKey(
      "raw",
      concat(staticShared, ephemeralShared),
      "HKDF",
      false,
      ["deriveBits"],
    );
    const okm = new Uint8Array(
      await crypto.subtle.deriveBits(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: HKDF_SALT,
          info: concat(HKDF_INFO, clientStatic, appStatic, clientEph, appEph),
        },
        ikm,
        512,
      ),
    );
    const aes = (bytes: Uint8Array<ArrayBuffer>, usage: KeyUsage) =>
      crypto.subtle.importKey("raw", bytes, "AES-GCM", false, [usage]);
    const clientToApp = okm.slice(0, 32);
    const appToClient = okm.slice(32, 64);
    okm.fill(0);
    staticShared.fill(0);
    ephemeralShared.fill(0);
    if (role === "extension") {
      return new Session(
        await aes(clientToApp, "encrypt"),
        await aes(appToClient, "decrypt"),
        CLIENT_TO_APP,
        APP_TO_CLIENT,
      );
    }
    return new Session(
      await aes(appToClient, "encrypt"),
      await aes(clientToApp, "decrypt"),
      APP_TO_CLIENT,
      CLIENT_TO_APP,
    );
  }

  /** Chiffre un message ; renvoie son compteur et le chiffré. */
  async seal(plaintext: Uint8Array<ArrayBuffer>): Promise<{ n: number; c: Uint8Array<ArrayBuffer> }> {
    if (this.sent >= MAX_MESSAGES) {
      throw new ProtocolError("session_epuisee", "session épuisée : rouvrir la liaison");
    }
    const n = this.sent;
    const c = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce(this.sendDirection, n), additionalData: AAD },
        this.sendKey,
        plaintext,
      ),
    );
    this.sent += 1;
    return { n, c };
  }

  /** Déchiffre le message suivant ; refuse tout message rejoué ou hors séquence. */
  async open(n: number, ciphertext: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
    if (!Number.isSafeInteger(n) || n !== this.received) {
      throw new ProtocolError("rejeu", `message rejoué ou hors séquence (attendu ${this.received}, reçu ${n})`);
    }
    let plaintext: ArrayBuffer;
    try {
      plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce(this.receiveDirection, n), additionalData: AAD },
        this.receiveKey,
        ciphertext,
      );
    } catch {
      throw new ProtocolError("message_altere", "message altéré ou d'une autre session");
    }
    this.received += 1;
    return new Uint8Array(plaintext);
  }
}

// --- Messages (voir crates/protocol/src/message.rs).

export type PairState = "confirmed" | "refused" | "expired";
export type Proximity = "same-origin" | "same-host" | "subdomain";

export type Envelope =
  | { type: "pair"; v: number; client: string; browser: string }
  | { type: "pair-pending"; v: number; app: string; pairing: string }
  | { type: "pair-result"; v: number; pairing: string; state: PairState }
  | { type: "hello"; v: number; client: string; eph: string }
  | { type: "welcome"; v: number; eph: string; n: number; c: string }
  | { type: "msg"; v: number; n: number; c: string }
  | { type: "error"; v: number; code: string; message: string };

export type Request =
  | { op: "status"; id: number }
  | { op: "entries"; id: number; url: string }
  | { op: "show"; id: number };

export interface SiteEntry {
  id: string;
  title: string;
  username: string;
  proximity: Proximity;
  insecure: boolean;
}

export type Response =
  | { op: "welcome"; app: string; version: string }
  | { op: "status"; id: number; unlocked: boolean }
  | { op: "entries"; id: number; entries: SiteEntry[] }
  | { op: "ok"; id: number }
  | { op: "error"; id: number | null; code: string; message: string };

/** Vérifie la forme d'une enveloppe reçue de l'application. */
export function parseEnvelope(raw: unknown): Envelope {
  if (!raw || typeof raw !== "object") {
    throw new ProtocolError("message_invalide", "message illisible");
  }
  const value = raw as Record<string, unknown>;
  if (value.v !== VERSION) {
    throw new ProtocolError("version", "version du protocole non prise en charge");
  }
  const text = (key: string) => typeof value[key] === "string";
  const counter = (key: string) => Number.isSafeInteger(value[key]) && (value[key] as number) >= 0;
  switch (value.type) {
    case "pair-pending":
      if (text("app") && text("pairing")) return value as Envelope;
      break;
    case "pair-result":
      if (text("pairing") && ["confirmed", "refused", "expired"].includes(value.state as string)) {
        return value as Envelope;
      }
      break;
    case "welcome":
      if (text("eph") && counter("n") && text("c")) return value as Envelope;
      break;
    case "msg":
      if (counter("n") && text("c")) return value as Envelope;
      break;
    case "error":
      if (text("code") && text("message")) return value as Envelope;
      break;
  }
  throw new ProtocolError("message_invalide", "message inattendu");
}

const decoder = new TextDecoder();

export function encodeJson(value: unknown): Uint8Array<ArrayBuffer> {
  return encoder.encode(JSON.stringify(value));
}

export function decodeResponse(bytes: Uint8Array): Response {
  let value: unknown;
  try {
    value = JSON.parse(decoder.decode(bytes));
  } catch {
    throw new ProtocolError("message_invalide", "réponse illisible");
  }
  if (!value || typeof value !== "object" || typeof (value as { op?: unknown }).op !== "string") {
    throw new ProtocolError("message_invalide", "réponse inattendue");
  }
  return value as Response;
}
