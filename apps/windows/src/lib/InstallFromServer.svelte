<script lang="ts">
  import { onMount } from "svelte";
  import { api, AppError, messageOf } from "./api";
  import { chooseExistingKeyfile, chooseNewVaultPath } from "./files";
  import { focusOnMount } from "./focus";
  import type { Status } from "./types";

  interface Props {
    onInstalled: (status: Status) => void;
    onCancel: () => void;
  }
  let { onInstalled, onCancel }: Props = $props();

  let server = $state("https://coffre.ligrivs.com");
  let account = $state("");
  let file = $state("coffre.kdbx");
  let serverPassword = $state("");
  let vaultPath = $state("");
  let passphrase = $state("");
  let keyfile = $state("");
  let busy = $state(false);
  let failure = $state<string | null>(null);

  let ready = $derived(
    !busy &&
      server.trim() !== "" &&
      account.trim() !== "" &&
      serverPassword !== "" &&
      vaultPath.trim() !== "" &&
      (passphrase !== "" || keyfile.trim() !== ""),
  );

  onMount(async () => {
    try {
      const paths = await api.defaultPaths();
      vaultPath = paths.vault;
      keyfile = paths.keyfile;
    } catch (error) {
      failure = messageOf(error);
    }
  });

  async function pickVaultPath() {
    const chosen = await chooseNewVaultPath(vaultPath);
    if (chosen) vaultPath = chosen;
  }

  async function pickKeyfile() {
    const chosen = await chooseExistingKeyfile();
    if (chosen) keyfile = chosen;
  }

  async function install(event: SubmitEvent) {
    event.preventDefault();
    if (!ready) return;
    busy = true;
    failure = null;
    try {
      const status = await api.installFromServer({
        server: server.trim(),
        account: account.trim(),
        file: file.trim(),
        serverPassword,
        path: vaultPath.trim(),
        passphrase,
        keyfilePath: keyfile.trim() === "" ? null : keyfile.trim(),
      });
      serverPassword = "";
      passphrase = "";
      onInstalled(status);
    } catch (error) {
      if (error instanceof AppError && error.code === "identifiants_refuses") {
        serverPassword = "";
      }
      failure = messageOf(error);
    } finally {
      busy = false;
    }
  }
</script>

<section class="panel">
  <h1>Installer le coffre du serveur</h1>
  <p class="muted">
    Ce PC télécharge le coffre déjà synchronisé par un autre PC, puis le garde à jour.
  </p>
  <form onsubmit={install}>
    <fieldset disabled={busy}>
      <legend>Serveur « coffre »</legend>
      <label for="serveur">Adresse du serveur</label>
      <input id="serveur" type="text" bind:value={server} spellcheck="false" />
      <label for="compte">Compte</label>
      <input id="compte" type="text" bind:value={account} spellcheck="false" autocomplete="off" {@attach focusOnMount} />
      <label for="mdp-serveur">Mot de passe du serveur</label>
      <input id="mdp-serveur" type="password" bind:value={serverPassword} autocomplete="off" />
      <label for="fichier">Nom du coffre sur le serveur</label>
      <input id="fichier" type="text" bind:value={file} spellcheck="false" />
      <p class="note small">
        Vérifiez le compte et le mot de passe avant de valider : après cinq refus en rafale, le serveur bloque votre
        adresse pendant 4 heures.
      </p>
    </fieldset>

    <fieldset disabled={busy}>
      <legend>Sur ce PC</legend>
      <label for="emplacement">Emplacement du coffre</label>
      <div class="row">
        <input id="emplacement" type="text" bind:value={vaultPath} spellcheck="false" />
        <button type="button" onclick={pickVaultPath}>Changer…</button>
      </div>
      <label for="phrase">Phrase de passe du coffre</label>
      <input id="phrase" type="password" bind:value={passphrase} autocomplete="off" />
      <label for="cle">Fichier clé <span class="muted">(copie de celui de l'autre PC)</span></label>
      <div class="row">
        <input id="cle" type="text" bind:value={keyfile} spellcheck="false" placeholder="Aucun" />
        <button type="button" onclick={pickKeyfile}>Choisir…</button>
      </div>
    </fieldset>

    {#if failure}<p class="error" role="alert">{failure}</p>{/if}

    <div class="actions">
      <button type="button" onclick={onCancel} disabled={busy}>Annuler</button>
      <button type="submit" class="primary" disabled={!ready}>
        {busy ? "Installation…" : "Installer"}
      </button>
    </div>
    {#if busy}
      <p class="muted small" aria-live="polite">Téléchargement et ouverture du coffre…</p>
    {/if}
  </form>
</section>
