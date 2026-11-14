// Fenêtre de l'extension : entrées du site ouvert, sans mot de passe (le
// remplissage arrive en semaine 4).

import { el, replace } from "./dom";
import type { EntriesAnswer, PageRequest, SimpleAnswer } from "./messages";
import type { SiteEntry } from "./protocol";

const content = document.getElementById("contenu") as HTMLElement;

function ask<T>(request: PageRequest): Promise<T> {
  return chrome.runtime.sendMessage(request) as Promise<T>;
}

function mention(entry: SiteEntry): string | null {
  const notes: string[] = [];
  if (entry.proximity === "subdomain") notes.push("autre sous-domaine");
  if (entry.proximity === "same-host") notes.push("même site, autre port");
  if (entry.insecure) notes.push("connexion non chiffrée (http)");
  return notes.length ? notes.join(" · ") : null;
}

function showEntries(host: string, entries: SiteEntry[]): void {
  if (entries.length === 0) {
    replace(content, el("p", { class: "muted", text: `Aucune entrée pour ${host}.` }));
    return;
  }
  const list = el("ul", { class: "entries" });
  for (const entry of entries) {
    const note = mention(entry);
    list.append(
      el(
        "li",
        {},
        el("span", { class: "title", text: entry.title || "(sans titre)" }),
        el("span", { class: "muted", text: entry.username || "(sans identifiant)" }),
        note ? el("div", { class: "mention", text: note }) : null,
      ),
    );
  }
  replace(
    content,
    el("p", { class: "muted small", text: `${entries.length} entrée${entries.length > 1 ? "s" : ""} pour ${host}` }),
    list,
  );
}

function showProblem(answer: Extract<EntriesAnswer, { ok: false }>): void {
  const actions = el("div", { class: "actions" });
  if (answer.code === "verrouille") {
    actions.append(
      el("button", {
        class: "primary",
        text: "Ouvrir l'application",
        onclick: () => {
          void ask<SimpleAnswer>({ kind: "montrer-application" }).then(() => window.close());
        },
      }),
    );
    replace(content, el("p", { text: "Le coffre est verrouillé : déverrouillez-le dans l'application." }), actions);
    return;
  }
  if (answer.code === "non_appaire") {
    actions.append(
      el("button", {
        class: "primary",
        text: "Appairer ce navigateur",
        onclick: () => {
          void chrome.runtime.openOptionsPage();
          window.close();
        },
      }),
    );
    replace(content, el("p", { text: answer.message }), actions);
    return;
  }
  replace(content, el("p", { class: answer.code === "page" ? "muted" : "error", text: answer.message }));
}

async function main(): Promise<void> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id === undefined) {
    replace(content, el("p", { class: "muted", text: "Aucun onglet." }));
    return;
  }
  const answer = await ask<EntriesAnswer>({ kind: "entrees", tabId: tab.id });
  if (answer.ok) showEntries(answer.host, answer.entries);
  else showProblem(answer);
}

void main().catch((error: unknown) => {
  replace(content, el("p", { class: "error", text: error instanceof Error ? error.message : String(error) }));
});
