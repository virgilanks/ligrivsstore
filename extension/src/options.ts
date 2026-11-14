// Page d'options : appairage avec l'application, confirmé des deux côtés.

import { el, replace } from "./dom";
import {
  PAIRING_PORT,
  type PageRequest,
  type PairingPortAnswer,
  type PairingPortMessage,
  type PairingStatus,
} from "./messages";

const zone = document.getElementById("etat") as HTMLElement;

function ask<T>(request: PageRequest): Promise<T> {
  return chrome.runtime.sendMessage(request) as Promise<T>;
}

function fingerprintBlock(fingerprint: string): HTMLElement {
  return el("p", { class: "fingerprint", text: fingerprint, ariaLabel: "Empreinte" });
}

async function render(): Promise<void> {
  const state = await ask<PairingStatus>({ kind: "etat" });
  if (state.paired && state.fingerprint) {
    replace(
      zone,
      el("p", { text: "Ce navigateur est appairé avec l'application. Empreinte de l'appairage :" }),
      fingerprintBlock(state.fingerprint),
      state.paired_at
        ? el("p", { class: "muted small", text: `Appairé le ${new Date(state.paired_at).toLocaleString("fr-FR")}.` })
        : null,
      el(
        "div",
        { class: "actions" },
        el("button", { text: "Appairer de nouveau", onclick: startPairing }),
        el("button", {
          text: "Oublier cet appairage",
          onclick: () => {
            void ask({ kind: "oublier" }).then(render);
          },
        }),
      ),
    );
    return;
  }
  replace(
    zone,
    el("p", { text: "Ce navigateur n'est pas encore appairé." }),
    el(
      "p",
      {
        class: "muted small",
        text: "L'application ligrivsstore doit être installée sur ce PC. Elle démarre seule si besoin.",
      },
    ),
    el("div", { class: "actions" }, el("button", { class: "primary", text: "Appairer avec l'application", onclick: startPairing })),
  );
}

function startPairing(): void {
  const port = chrome.runtime.connect({ name: PAIRING_PORT });
  // Signal de vie : le service worker reste éveillé pendant l'attente.
  const keepAlive = setInterval(() => {
    try {
      port.postMessage({ kind: "veille" } satisfies PairingPortAnswer);
    } catch {
      clearInterval(keepAlive);
    }
  }, 15_000);
  port.onDisconnect.addListener(() => clearInterval(keepAlive));
  replace(zone, el("p", { class: "muted", text: "Connexion à l'application…" }));
  port.onMessage.addListener((message: PairingPortMessage) => {
    switch (message.kind) {
      case "empreinte":
        replace(
          zone,
          el("p", { text: "L'application affiche une demande d'appairage. Vérifiez qu'elle montre exactement cette empreinte :" }),
          fingerprintBlock(message.fingerprint),
          el("p", { text: "Si c'est le cas, confirmez l'appairage dans l'application. Sinon, refusez-le." }),
          el("p", { class: "muted small", text: "En attente de votre décision dans l'application (deux minutes au plus)…" }),
        );
        break;
      case "issue":
        if (message.state === "confirmed") {
          replace(
            zone,
            el("p", { text: "L'application a confirmé l'appairage. L'empreinte qu'elle affichait était-elle exactement celle-ci ?" }),
            fingerprintBlock(message.fingerprint),
            el(
              "div",
              { class: "actions" },
              el("button", {
                class: "primary",
                text: "Oui, identique",
                onclick: () => port.postMessage({ kind: "empreintes-identiques", same: true } satisfies PairingPortAnswer),
              }),
              el("button", {
                text: "Non, différente",
                onclick: () => {
                  port.postMessage({ kind: "empreintes-identiques", same: false } satisfies PairingPortAnswer);
                  replace(
                    zone,
                    el("p", { class: "error", text: "Appairage abandonné : révoquez ce navigateur dans l'onglet « Navigateurs » de l'application." }),
                    el("div", { class: "actions" }, el("button", { text: "Recommencer", onclick: () => void render() })),
                  );
                  port.disconnect();
                },
              }),
            ),
          );
        } else {
          replace(
            zone,
            el("p", {
              class: "error",
              text: message.state === "refused" ? "L'appairage a été refusé dans l'application." : "Sans réponse de l'application, la demande a expiré.",
            }),
            el("div", { class: "actions" }, el("button", { text: "Recommencer", onclick: startPairing })),
          );
          port.disconnect();
        }
        break;
      case "enregistre":
        port.disconnect();
        void render();
        break;
      case "erreur":
        replace(
          zone,
          el("p", { class: "error", text: message.message }),
          el("div", { class: "actions" }, el("button", { text: "Recommencer", onclick: startPairing })),
        );
        port.disconnect();
        break;
    }
  });
}

void render().catch((error: unknown) => {
  replace(zone, el("p", { class: "error", text: error instanceof Error ? error.message : String(error) }));
});
