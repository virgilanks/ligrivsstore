<script lang="ts">
  import { onMount } from "svelte";
  import { api, messageOf } from "./api";
  import { formatDate } from "./format";
  import type { SyncSettingsView, SyncStatusView } from "./types";

  interface Props {
    sync: SyncStatusView | null;
  }
  let { sync }: Props = $props();

  let view = $state<SyncSettingsView | null>(null);
  let server = $state("");
  let account = $state("");
  let file = $state("");
  let password = $state("");
  let busy = $state(false);
  let failure = $state<string | null>(null);
  let notice = $state<string | null>(null);

  function fill(next: SyncSettingsView) {
    view = next;
    server = next.server;
    account = next.account;
    file = next.file;
    password = "";
  }

  onMount(async () => {
    try {
      fill(await api.getSyncSettings());
    } catch (error) {
      failure = messageOf(error);
    }
  });

  async function save(event: SubmitEvent) {
    event.preventDefault();
    busy = true;
    failure = null;
    notice = null;
    try {
      fill(
        await api.configureSync({
          server: server.trim(),
          account: account.trim(),
          file: file.trim(),
          password: password === "" ? null : password,
        }),
      );
      notice = "Réglage enregistré dans le coffre : synchronisation en cours.";
    } catch (error) {
      failure = messageOf(error);
    } finally {
      password = "";
      busy = false;
    }
  }

  async function syncNow() {
    failure = null;
    notice = null;
    try {
      await api.syncNow();
      notice = "Synchronisation demandée.";
    } catch (error) {
      failure = messageOf(error);
    }
  }

  const STATES: Record<SyncStatusView["state"], string> = {
    non_configuree: "Non réglée : ce coffre reste sur ce PC.",
    en_attente: "Première synchronisation imminente.",
    en_cours: "Échange en cours avec le serveur…",
    a_jour: "À jour.",
    hors_ligne: "Serveur injoignable : nouvel essai automatique dans quelques minutes.",
    suspendue:
      "Suspendue : le serveur a refusé le compte ou le mot de passe. Saisissez-les de nouveau ci-dessous ; aucun essai n'est fait d'ici là, car le serveur bloque votre adresse après cinq refus en rafale.",
    erreur: "En échec : voir le détail ci-dessous.",
  };
</script>

<div class="sync-panel">
  <h2>Synchronisation</h2>
  {#if sync}
    <p class="state-line state-{sync.state}" role="status">{STATES[sync.state]}</p>
    {#if sync.message && (sync.state === "erreur" || sync.state === "hors_ligne")}
      <p class="error small">{sync.message}</p>
    {/if}
    <p class="muted small">Dernier échange réussi : {formatDate(sync.lastSuccess)}.</p>
  {/if}
  <p class="muted small">
    Le coffre est synchronisé à l'ouverture, 10 secondes après chaque modification, puis toutes les 15 minutes. Le
    serveur ne reçoit que le fichier chiffré. Ce réglage est rangé dans le coffre : vos autres PC le reçoivent
    avec lui.
  </p>

  {#if view}
    <form onsubmit={save}>
      <fieldset disabled={busy}>
        <legend>Serveur « coffre »</legend>
        <label for="sync-serveur">Adresse du serveur</label>
        <input id="sync-serveur" type="text" bind:value={server} spellcheck="false" />
        <label for="sync-compte">Compte</label>
        <input id="sync-compte" type="text" bind:value={account} spellcheck="false" autocomplete="off" />
        <label for="sync-fichier">Nom du coffre sur le serveur</label>
        <input id="sync-fichier" type="text" bind:value={file} spellcheck="false" />
        <label for="sync-mdp">Mot de passe du serveur</label>
        <input
          id="sync-mdp"
          type="password"
          bind:value={password}
          autocomplete="off"
          placeholder={view.hasPassword ? "Laisser vide pour garder l'actuel" : ""}
        />
      </fieldset>
      {#if failure}<p class="error" role="alert">{failure}</p>{/if}
      {#if notice}<p class="note small" role="status">{notice}</p>{/if}
      <div class="actions">
        {#if view.configured}
          <button type="button" onclick={syncNow} disabled={busy || sync?.state === "en_cours"}>
            Synchroniser maintenant
          </button>
        {/if}
        <button type="submit" class="primary" disabled={busy || account.trim() === "" || (!view.hasPassword && password === "")}>
          {busy ? "Vérification…" : "Enregistrer"}
        </button>
      </div>
    </form>
  {:else if failure}
    <p class="error" role="alert">{failure}</p>
  {/if}
</div>
