<script lang="ts">
  import { onMount } from "svelte";
  import { api, messageOf } from "./api";
  import type { Preferences } from "./types";

  let preferences = $state<Preferences | null>(null);
  let autostart = $state<boolean | null>(null);
  let autostartBusy = $state(false);
  let busy = $state(false);
  let failure = $state<string | null>(null);
  let notice = $state<string | null>(null);

  onMount(async () => {
    try {
      preferences = await api.getPreferences();
    } catch (error) {
      failure = messageOf(error);
    }
    try {
      autostart = await api.getAutostart();
    } catch {
      autostart = null;
    }
  });

  async function toggleAutostart(event: Event) {
    const wanted = (event.currentTarget as HTMLInputElement).checked;
    autostartBusy = true;
    failure = null;
    notice = null;
    try {
      autostart = await api.setAutostart(wanted);
      notice = autostart
        ? "ligrivsstore démarrera avec Windows, caché dans la zone de notification."
        : "ligrivsstore ne démarrera plus avec Windows.";
    } catch (error) {
      failure = messageOf(error);
      autostart = !wanted;
    } finally {
      autostartBusy = false;
    }
  }

  async function save(event: SubmitEvent) {
    event.preventDefault();
    if (!preferences) return;
    const { lockMinutes, clipboardSeconds } = preferences;
    if (!Number.isInteger(lockMinutes) || lockMinutes < 1 || lockMinutes > 60) {
      failure = "Délai de verrouillage : un nombre entier de minutes, de 1 à 60.";
      return;
    }
    if (!Number.isInteger(clipboardSeconds) || clipboardSeconds < 10 || clipboardSeconds > 120) {
      failure = "Effacement du presse-papiers : un nombre entier de secondes, de 10 à 120.";
      return;
    }
    busy = true;
    failure = null;
    notice = null;
    try {
      preferences = await api.savePreferences($state.snapshot(preferences));
      notice = "Réglages enregistrés.";
    } catch (error) {
      failure = messageOf(error);
    } finally {
      busy = false;
    }
  }
</script>

<div class="settings">
  <h2>Réglages</h2>
  {#if preferences}
    <form onsubmit={save}>
      <label for="verrouillage">Verrouiller après une inactivité de</label>
      <div class="row narrow-row">
        <input id="verrouillage" type="number" min="1" max="60" step="1" bind:value={preferences.lockMinutes} disabled={busy} />
        <span>minutes (1 à 60)</span>
      </div>
      <p class="muted small">
        Le coffre se verrouille aussi avec la session Windows (Windows + L), à la mise en veille et quand vous quittez
        l'application. Fermer la fenêtre la garde dans la zone de notification, pour l'extension ; le délai
        d'inactivité continue de courir.
      </p>
      <label for="presse-papiers">Effacer le presse-papiers après</label>
      <div class="row narrow-row">
        <input id="presse-papiers" type="number" min="10" max="120" step="5" bind:value={preferences.clipboardSeconds} disabled={busy} />
        <span>secondes (10 à 120)</span>
      </div>
      <p class="muted small">
        Un identifiant ou un mot de passe copié n'entre ni dans l'historique du presse-papiers (Windows + V) ni dans le
        presse-papiers cloud. Il est effacé après ce délai, si vous n'avez rien copié d'autre entre-temps.
      </p>
      {#if autostart !== null}
        <label class="check">
          <input type="checkbox" checked={autostart} onchange={toggleAutostart} disabled={autostartBusy} />
          Démarrer avec Windows, caché dans la zone de notification
        </label>
        <p class="muted small">
          Sans cela, l'extension démarre l'application quand elle en a besoin. Le coffre reste verrouillé jusqu'à ce
          que vous l'ouvriez.
        </p>
      {/if}
      {#if failure}<p class="error" role="alert">{failure}</p>{/if}
      {#if notice}<p class="note small" role="status">{notice}</p>{/if}
      <div class="actions">
        <button type="submit" class="primary" disabled={busy}>{busy ? "Enregistrement…" : "Enregistrer"}</button>
      </div>
    </form>
  {:else if failure}
    <p class="error" role="alert">{failure}</p>
  {/if}
</div>
