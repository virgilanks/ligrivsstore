// Liaison avec l'application, côté service worker : messagerie native vers le
// relais ligrivsstore-pont, appairage, puis session chiffrée.

import {
  type Envelope,
  type KeyPairRaw,
  type PairState,
  ProtocolError,
  type Request,
  type Response,
  Session,
  VERSION,
  HOST_NAME,
  checkKey,
  decodeResponse,
  encodeJson,
  fingerprint,
  fromBase64,
  generateKeyPair,
  parseEnvelope,
  toBase64,
} from "./protocol";

/** Délai d'une réponse de l'application (hors appairage). Le premier message
 * peut attendre que le relais démarre l'application : 15 secondes au plus. */
const ANSWER_MS = 30_000;
/** Délai d'un appairage : l'application attend deux minutes la décision. */
const PAIRING_MS = 130_000;

type Waiter = { resolve: (value: Envelope) => void; reject: (error: Error) => void; timer: number };

/** Une liaison : un port de messagerie native, des réponses dans l'ordre. */
export class NativeLink {
  private readonly port: chrome.runtime.Port;
  private readonly waiters: Waiter[] = [];
  private readonly queue: Envelope[] = [];
  private closedWith: Error | null = null;

  constructor() {
    this.port = chrome.runtime.connectNative(HOST_NAME);
    this.port.onMessage.addListener((raw: unknown) => {
      let envelope: Envelope;
      try {
        envelope = parseEnvelope(raw);
      } catch (error) {
        this.fail(error as Error);
        return;
      }
      const waiter = this.waiters.shift();
      if (waiter) {
        clearTimeout(waiter.timer);
        waiter.resolve(envelope);
      } else {
        this.queue.push(envelope);
      }
    });
    this.port.onDisconnect.addListener(() => {
      const reason = chrome.runtime.lastError?.message ?? "liaison fermée";
      this.fail(
        new ProtocolError(
          "application_absente",
          reason.includes("not found") || reason.includes("Specified native messaging host")
            ? "relais ligrivsstore introuvable : installez ou réinstallez l'application ligrivsstore"
            : `liaison avec l'application fermée (${reason})`,
        ),
      );
    });
  }

  private fail(error: Error): void {
    this.closedWith = error;
    for (const waiter of this.waiters.splice(0)) {
      clearTimeout(waiter.timer);
      waiter.reject(error);
    }
  }

  send(envelope: Envelope): void {
    if (this.closedWith) throw this.closedWith;
    this.port.postMessage(envelope);
  }

  /** Prochain message de l'application. */
  receive(timeoutMs = ANSWER_MS): Promise<Envelope> {
    const queued = this.queue.shift();
    if (queued) return Promise.resolve(queued);
    if (this.closedWith) return Promise.reject(this.closedWith);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const index = this.waiters.findIndex((w) => w.timer === timer);
        if (index >= 0) this.waiters.splice(index, 1);
        reject(new ProtocolError("delai", "l'application ne répond pas"));
      }, timeoutMs) as unknown as number;
      this.waiters.push({ resolve, reject, timer });
    });
  }

  close(): void {
    this.closedWith ??= new ProtocolError("ferme", "liaison fermée");
    this.port.disconnect();
  }
}

function errorOf(envelope: Envelope): ProtocolError {
  if (envelope.type === "error") return new ProtocolError(envelope.code, envelope.message);
  return new ProtocolError("message_invalide", `réponse inattendue : ${envelope.type}`);
}

/** Étapes d'un appairage, pour la page d'options. */
export interface PairingProgress {
  /** L'application a reçu la demande : empreinte à comparer. */
  onPending(fingerprint: string): void;
}

/** Demande d'appairage : renvoie l'issue et la clé publique de l'application. */
export async function pair(
  identity: KeyPairRaw,
  browser: string,
  progress: PairingProgress,
): Promise<{ state: PairState; appPublic: Uint8Array<ArrayBuffer>; fingerprint: string }> {
  const link = new NativeLink();
  try {
    link.send({ type: "pair", v: VERSION, client: toBase64(identity.publicRaw), browser });
    const pending = await link.receive();
    if (pending.type !== "pair-pending") throw errorOf(pending);
    const appPublic = checkKey(fromBase64(pending.app));
    const shown = await fingerprint(appPublic, identity.publicRaw);
    progress.onPending(shown);
    const result = await link.receive(PAIRING_MS);
    if (result.type !== "pair-result" || result.pairing !== pending.pairing) throw errorOf(result);
    return { state: result.state, appPublic, fingerprint: shown };
  } finally {
    link.close();
  }
}

/** Session chiffrée ouverte avec l'application appairée. */
export class SecureLink {
  private nextId = 1;

  private constructor(
    private readonly link: NativeLink,
    private readonly session: Session,
  ) {}

  static async open(identity: KeyPairRaw, appPublic: Uint8Array<ArrayBuffer>): Promise<SecureLink> {
    const link = new NativeLink();
    try {
      const ephemeral = await generateKeyPair();
      link.send({
        type: "hello",
        v: VERSION,
        client: toBase64(identity.publicRaw),
        eph: toBase64(ephemeral.publicRaw),
      });
      const welcome = await link.receive();
      if (welcome.type !== "welcome") throw errorOf(welcome);
      const session = await Session.establish(
        "extension",
        identity,
        ephemeral,
        appPublic,
        checkKey(fromBase64(welcome.eph)),
      );
      // Le premier message prouve que l'application détient sa clé.
      const first = decodeResponse(await session.open(welcome.n, fromBase64(welcome.c)));
      if (first.op !== "welcome") {
        throw new ProtocolError("message_invalide", "accueil inattendu");
      }
      return new SecureLink(link, session);
    } catch (error) {
      link.close();
      throw error;
    }
  }

  /** Envoie une requête chiffrée et attend sa réponse. */
  async request(build: (id: number) => Request): Promise<Response> {
    const request = build(this.nextId);
    this.nextId += 1;
    const { n, c } = await this.session.seal(encodeJson(request));
    this.link.send({ type: "msg", v: VERSION, n, c: toBase64(c) });
    const answer = await this.link.receive();
    if (answer.type !== "msg") throw errorOf(answer);
    const response = decodeResponse(await this.session.open(answer.n, fromBase64(answer.c)));
    if (response.op === "error") throw new ProtocolError(response.code, response.message);
    return response;
  }

  close(): void {
    this.link.close();
  }
}
