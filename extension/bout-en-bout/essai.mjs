// Essai de bout en bout, sous Linux, de la liaison extension ↔ application :
// Chromium (Playwright) avec l'extension, relais ligrivsstore-pont déclaré au
// navigateur, application compilée sous un écran virtuel (Xvfb), coffre
// d'essai créé par l'outil lgs.
//
// Déroulé : le relais démarre l'application (cachée, coffre verrouillé) ;
// appairage confirmé des deux côtés ; « coffre verrouillé » ; déverrouillage ;
// entrées de la page ; domaines piégés écartés ; fenêtre fermée, donc cachée,
// coffre toujours ouvert ; fenêtre montrée à la demande de l'extension.
//
// Prérequis : extension construite (node build.mjs --bout-en-bout), relais et
// outil lgs compilés (cargo build -p ligrivsstore-bridge -p ligrivsstore-cli),
// application compilée (npm run tauri -- build --debug --no-bundle, dans
// apps/windows), Xvfb, openbox (gestionnaire de fenêtres) et xdotool.
// Lancement, depuis extension/ :
//   dbus-run-session -- node bout-en-bout/essai.mjs
// Pour l'essai seulement : jamais de vrai coffre ni de vrai mot de passe.

import { execFileSync, spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

const racine = resolve(import.meta.dirname, "../..");
const extension = resolve(racine, "extension/dist-bout-en-bout");
const relais = resolve(racine, "target/debug/ligrivsstore-pont");
const lgs = resolve(racine, "target/debug/lgs");
const application = resolve(racine, "apps/windows/src-tauri/target/debug/ligrivsstore");
const ID = "pbjfabapbnileccikicpifdnhkocnlbb";
const PHRASE = "essai-bout-en-bout-lagune-pivoine";
const PORT = 8765;
const ECRAN = ":93";

for (const chemin of [extension, relais, lgs, application]) {
  if (!existsSync(chemin)) throw new Error(`absent : ${chemin}`);
}

const travail = mkdtempSync(join(tmpdir(), "lgs-bout-en-bout-"));
const maison = join(travail, "maison");
const config = join(maison, ".config", "com.ligrivs.ligrivsstore");
mkdirSync(config, { recursive: true });
const canal = join(travail, "canal", "canal.sock");
const coffre = join(travail, "coffre.kdbx");
const captures = process.env.CAPTURES ?? travail;
const resultats = [];

function verifie(intitule, condition, detail = "") {
  resultats.push({ intitule, ok: Boolean(condition) });
  console.log(`${condition ? "RÉUSSI " : "ÉCHOUÉ "} ${intitule}${detail ? ` — ${detail}` : ""}`);
}

const attendre = (ms) => new Promise((r) => setTimeout(r, ms));

// 1. Coffre d'essai et réglages de l'application.
const envLgs = { ...process.env, LGS_PASSWORD: PHRASE };
execFileSync(lgs, ["new", coffre, "--calibrate-ms", "50"], { env: envLgs, stdio: "ignore" });
for (const [titre, adresse, identifiant] of [
  ["Exemple", `http://www.exemple.test:${PORT}`, "hermann"],
  ["Exemple compte", `http://compte.exemple.test:${PORT}/connexion`, "hermann.compte"],
  ["Autre domaine", `http://autre-exemple.test:${PORT}`, "piege-1"],
  ["Domaine piégé", `http://www.exemple.test.piege.test:${PORT}`, "piege-2"],
  ["Même site en https", `https://www.exemple.test`, "piege-3"],
]) {
  execFileSync(lgs, ["add", coffre, "--title", titre, "--url", adresse, "--username", identifiant, "--generate", "16"], {
    env: envLgs,
    stdio: "ignore",
  });
}
writeFileSync(join(config, "reglages.json"), JSON.stringify({ lastVault: coffre, lockMinutes: 10 }));

// 2. Relais déclaré au navigateur, avec le canal et l'application d'essai.
const enveloppe = join(travail, "pont.sh");
writeFileSync(
  enveloppe,
  [
    "#!/bin/sh",
    `export LIGRIVSSTORE_CANAL='${canal}'`,
    `export LIGRIVSSTORE_APPLICATION='${application}'`,
    `export HOME='${maison}'`,
    `export XDG_CONFIG_HOME='${join(maison, ".config")}'`,
    `export DISPLAY='${ECRAN}'`,
    `exec '${relais}' "$@"`,
    "",
  ].join("\n"),
);
chmodSync(enveloppe, 0o755);
const profil = join(travail, "profil");
mkdirSync(join(profil, "NativeMessagingHosts"), { recursive: true });
const manifeste = JSON.stringify({
  name: "com.ligrivs.ligrivsstore",
  description: "ligrivsstore (essai)",
  path: enveloppe,
  type: "stdio",
  allowed_origins: [`chrome-extension://${ID}/`],
});
writeFileSync(join(profil, "NativeMessagingHosts", "com.ligrivs.ligrivsstore.json"), manifeste);
// Selon les versions, Chromium cherche aussi dans le dossier par défaut.
for (const dossier of [join(process.env.HOME ?? "/root", ".config", "chromium", "NativeMessagingHosts")]) {
  mkdirSync(dossier, { recursive: true });
  writeFileSync(join(dossier, "com.ligrivs.ligrivsstore.json"), manifeste);
}

// 3. Écran virtuel, gestionnaire de fenêtres et page de connexion locale.
const xvfb = spawn("Xvfb", [ECRAN, "-screen", "0", "1280x900x24", "-nolisten", "tcp"], { stdio: "ignore" });
await attendre(800);
const gestionnaire = spawn("openbox", [], { env: { ...process.env, DISPLAY: ECRAN }, stdio: "ignore" });
const serveur = createServer((_, res) => {
  res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  res.end('<!doctype html><title>Connexion</title><form><input name="u"><input type="password" name="p"></form>');
}).listen(PORT, "127.0.0.1");
await attendre(800);

const xdotool = (...args) =>
  execFileSync("xdotool", args, { env: { ...process.env, DISPLAY: ECRAN }, encoding: "utf8" }).trim();
const fenetreApplication = () => {
  try {
    return xdotool("search", "--onlyvisible", "--name", "^ligrivsstore$").split("\n")[0];
  } catch {
    return null;
  }
};
/** Attend que la fenêtre de l'application soit visible (ou cachée). */
async function attendreFenetre(visible, essais = 40) {
  for (let i = 0; i < essais; i += 1) {
    const trouvee = fenetreApplication();
    if (visible ? trouvee : !trouvee) return trouvee;
    await attendre(250);
  }
  return visible ? null : fenetreApplication();
}
/** Met la fenêtre au premier plan : les touches passent ensuite par le
 * serveur X (XTEST), comme celles d'un vrai clavier. */
async function activer(fenetre) {
  xdotool("windowactivate", "--sync", fenetre);
  await attendre(400);
}
const processusVivant = () => {
  try {
    execFileSync("pgrep", ["-f", application]);
    return true;
  } catch {
    return false;
  }
};
const capture = (nom) => {
  try {
    execFileSync("import", ["-window", "root", join(captures, nom)], { env: { ...process.env, DISPLAY: ECRAN } });
  } catch {
    // capture facultative
  }
};

let contexte;
try {
  contexte = await chromium.launchPersistentContext(profil, {
    headless: false,
    env: { ...process.env, DISPLAY: ECRAN },
    args: [
      `--disable-extensions-except=${extension}`,
      `--load-extension=${extension}`,
      "--host-resolver-rules=MAP *.test 127.0.0.1",
      "--no-first-run",
    ],
  });
  let [travailleur] = contexte.serviceWorkers();
  travailleur ??= await contexte.waitForEvent("serviceworker");
  verifie("extension chargée avec l'identifiant attendu", travailleur.url().startsWith(`chrome-extension://${ID}/`), travailleur.url());

  const cible = await contexte.newPage();
  await cible.goto(`http://www.exemple.test:${PORT}/connexion`);
  const options = await contexte.newPage();
  await options.goto(`chrome-extension://${ID}/options.html`);
  verifie("non appairé au départ", await options.getByText("pas encore appairé").isVisible());

  // 4. Appairage : le relais démarre l'application, qui montre la demande.
  await options.getByRole("button", { name: "Appairer avec l'application" }).click();
  await options.locator(".fingerprint").waitFor({ timeout: 30_000 });
  const empreinteExtension = (await options.locator(".fingerprint").textContent()).trim();
  verifie("empreinte affichée par l'extension (six groupes)", /^(\d{5} ){5}\d{5}$/.test(empreinteExtension), empreinteExtension);
  let fenetre = await attendreFenetre(true);
  verifie("le relais a démarré l'application, qui montre la demande", fenetre !== null);
  await attendre(1500);
  capture("1-demande-appairage.png");
  // Confirmation dans l'application : le bouton « Refuser » a le focus,
  // « Confirmer l'appairage » vient ensuite.
  await activer(fenetre);
  xdotool("key", "Tab");
  xdotool("key", "Return");
  await options.getByRole("button", { name: "Oui, identique" }).waitFor({ timeout: 15_000 });
  await options.getByRole("button", { name: "Oui, identique" }).click();
  await options.getByText("Ce navigateur est appairé").waitFor({ timeout: 10_000 });
  const registre = JSON.parse(execFileSync("cat", [join(config, "navigateurs.json")], { encoding: "utf8" }));
  const appaire = registre.browsers?.[0];
  verifie("appairage retenu par l'application", appaire?.browser === "Chromium", appaire?.browser);
  verifie("même empreinte des deux côtés", appaire?.fingerprint === empreinteExtension);
  capture("2-appaire.png");

  // 5. Coffre verrouillé : l'extension le sait.
  const entrees = () =>
    options.evaluate(async (adresse) => {
      const [onglet] = await chrome.tabs.query({ url: adresse });
      return chrome.runtime.sendMessage({ kind: "entrees", tabId: onglet.id });
    }, `http://www.exemple.test:${PORT}/*`);
  const verrouille = await entrees();
  verifie("coffre verrouillé signalé", verrouille.ok === false && verrouille.code === "verrouille", JSON.stringify(verrouille));

  // 6. Déverrouillage dans l'application, puis entrées de la page.
  await activer(fenetre);
  xdotool("type", "--delay", "15", PHRASE);
  xdotool("key", "Return");
  let liste = null;
  for (let i = 0; i < 40; i += 1) {
    await attendre(500);
    liste = await entrees();
    if (liste.ok) break;
  }
  // La liste de l'application se charge juste après le déverrouillage.
  await attendre(1000);
  capture("3-deverrouille.png");
  verifie("entrées de la page reçues", liste?.ok === true, JSON.stringify(liste));
  const titres = (liste?.entries ?? []).map((e) => e.title);
  verifie("même origine en premier, puis autre sous-domaine", JSON.stringify(titres) === JSON.stringify(["Exemple", "Exemple compte"]), JSON.stringify(titres));
  verifie(
    "proximités et page non chiffrée signalées",
    liste?.entries?.[0]?.proximity === "same-origin" &&
      liste?.entries?.[1]?.proximity === "subdomain" &&
      liste.entries.every((e) => e.insecure === true),
  );
  verifie("domaines piégés et entrée https écartés", !titres.some((t) => /piégé|Autre|https/.test(t)));
  verifie("aucun mot de passe transmis", !JSON.stringify(liste).includes("password"));

  // 7. Fermer la fenêtre la cache, sans arrêter l'application ni verrouiller
  // le coffre (décision 0012) ; l'extension la montre ensuite.
  await activer(fenetre);
  xdotool("key", "alt+F4");
  const cachee = (await attendreFenetre(false)) === null;
  verifie("fenêtre fermée : cachée, application toujours lancée", cachee && processusVivant());
  const apresFermeture = await entrees();
  verifie("coffre toujours ouvert après la fermeture de la fenêtre", apresFermeture.ok === true, JSON.stringify(apresFermeture).slice(0, 120));
  const montre = await options.evaluate(() => chrome.runtime.sendMessage({ kind: "montrer-application" }));
  fenetre = await attendreFenetre(true);
  verifie("fenêtre montrée à la demande de l'extension", montre.ok === true && fenetre !== null, JSON.stringify(montre));
  capture("4-montree.png");

  // 8. La fenêtre de l'extension, ouverte comme une page, sur un onglet sans site.
  const fenetreExtension = await contexte.newPage();
  await fenetreExtension.goto(`chrome-extension://${ID}/popup.html`);
  await fenetreExtension.getByText("Rien à proposer sur cette page").waitFor({ timeout: 10_000 });
  verifie("fenêtre de l'extension : rien sur une page interne", true);
} catch (erreur) {
  verifie("déroulé complet", false, erreur instanceof Error ? erreur.message : String(erreur));
  capture("echec.png");
} finally {
  await contexte?.close().catch(() => {});
  serveur.close();
  try {
    execFileSync("pkill", ["-f", application]);
  } catch {
    // déjà arrêtée
  }
  gestionnaire.kill();
  xvfb.kill();
}

const echecs = resultats.filter((r) => !r.ok).length;
console.log(`\nRÉSULTAT : ${resultats.length - echecs} réussis, ${echecs} échoués (captures : ${captures})`);
process.exit(echecs ? 1 : 0);
