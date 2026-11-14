// Service worker de l'extension : seul à parler à l'application. Il lit
// l'adresse de la page dans l'onglet (navigateur), jamais dans la page.

import { forgetAll, loadKeyPair, loadPairing, saveKeyPair, savePairing } from "./keystore";
import { SecureLink, pair } from "./link";
import {
  type EntriesAnswer,
  PAIRING_PORT,
  type PageRequest,
  type PairingPortAnswer,
  type PairingPortMessage,
  type PairingStatus,
  type SimpleAnswer,
} from "./messages";
import { ProtocolError, generateKeyPair } from "./protocol";

/** Nom du navigateur, pour la liste de l'application. */
function browserName(): string {
  const data = (navigator as Navigator & { userAgentData?: { brands?: { brand: string }[] } }).userAgentData;
  const brands = data?.brands?.map((b) => b.brand) ?? [];
  if (brands.includes("Microsoft Edge")) return "Edge";
  if (brands.includes("Google Chrome")) return "Chrome";
  return "Chromium";
}

function failure(error: unknown): { ok: false; code: string; message: string } {
  if (error instanceof ProtocolError) return { ok: false, code: error.code, message: error.message };
  return { ok: false, code: "interne", message: error instanceof Error ? error.message : String(error) };
}

/** Vrai pour un message venu d'une page de l'extension elle-même. */
function fromOwnPage(sender: chrome.runtime.MessageSender, page?: string): boolean {
  if (sender.id !== chrome.runtime.id || !sender.url) return false;
  const base = chrome.runtime.getURL(page ?? "");
  return page ? sender.url.split("#")[0]?.split("?")[0] === base : sender.url.startsWith(base);
}

async function status(): Promise<PairingStatus> {
  const pairing = await loadPairing();
  return {
    paired: pairing !== null,
    fingerprint: pairing?.fingerprint ?? null,
    paired_at: pairing?.paired ?? null,
  };
}

async function openSession(): Promise<SecureLink> {
  const [identity, pairing] = await Promise.all([loadKeyPair(), loadPairing()]);
  if (!identity || !pairing) {
    throw new ProtocolError(
      "non_appaire",
      "Ce navigateur n'est pas appairé avec l'application : ouvrez les options de l'extension.",
    );
  }
  return SecureLink.open(identity, pairing.appPublic);
}

async function entries(tabId: number): Promise<EntriesAnswer> {
  const tab = await chrome.tabs.get(tabId);
  const url = tab.url ?? "";
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { ok: false, code: "page", message: "Rien à proposer sur cette page." };
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return { ok: false, code: "page", message: "Rien à proposer sur cette page." };
  }
  const link = await openSession();
  try {
    const response = await link.request((id) => ({ op: "entries", id, url }));
    if (response.op !== "entries") throw new ProtocolError("message_invalide", "réponse inattendue");
    return { ok: true, host: parsed.host, entries: response.entries };
  } finally {
    link.close();
  }
}

async function showApplication(): Promise<SimpleAnswer> {
  const link = await openSession();
  try {
    await link.request((id) => ({ op: "show", id }));
    return { ok: true };
  } finally {
    link.close();
  }
}

chrome.runtime.onMessage.addListener((message: PageRequest, sender, sendResponse) => {
  if (!fromOwnPage(sender)) return false;
  const work = (async () => {
    switch (message.kind) {
      case "etat":
        return status();
      case "entrees":
        return entries(message.tabId);
      case "montrer-application":
        return showApplication();
      case "oublier":
        await forgetAll();
        return { ok: true } satisfies SimpleAnswer;
    }
  })();
  work.then(sendResponse, (error: unknown) => sendResponse(failure(error)));
  return true;
});

/** Appairage, piloté par la page d'options sur un port dédié. */
async function runPairing(port: chrome.runtime.Port): Promise<void> {
  const post = (message: PairingPortMessage) => {
    try {
      port.postMessage(message);
    } catch {
      // Page fermée : l'appairage s'arrête là.
    }
  };
  let answered: (answer: PairingPortAnswer | null) => void = () => {};
  const comparison = new Promise<PairingPortAnswer | null>((resolve) => (answered = resolve));
  port.onMessage.addListener((message: PairingPortAnswer) => {
    if (message.kind === "empreintes-identiques") answered(message);
  });
  port.onDisconnect.addListener(() => answered(null));
  try {
    let identity = await loadKeyPair();
    if (!identity) {
      identity = await generateKeyPair();
      await saveKeyPair(identity);
    }
    const result = await pair(identity, browserName(), {
      onPending: (fingerprint) => post({ kind: "empreinte", fingerprint }),
    });
    post({ kind: "issue", state: result.state, fingerprint: result.fingerprint });
    if (result.state !== "confirmed") return;
    // Confirmation des deux côtés : l'utilisateur dit aussi, ici, que
    // l'empreinte affichée par l'application était la même.
    const answer = await comparison;
    if (answer?.kind === "empreintes-identiques" && answer.same) {
      await savePairing({
        appPublic: result.appPublic,
        fingerprint: result.fingerprint,
        paired: new Date().toISOString(),
      });
      post({ kind: "enregistre" });
    }
  } catch (error) {
    const { code, message } = failure(error);
    post({ kind: "erreur", code, message });
  }
}

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== PAIRING_PORT || !port.sender || !fromOwnPage(port.sender, "options.html")) {
    port.disconnect();
    return;
  }
  void runPairing(port);
});
