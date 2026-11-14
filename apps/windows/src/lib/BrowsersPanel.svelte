<script lang="ts">
  import { onMount } from "svelte";
  import { api, messageOf } from "./api";
  import { formatDate, since } from "./format";
  import type { BrowserView } from "./types";

  let browsers = $state<BrowserView[] | null>(null);
  let busy = $state<string | null>(null);
  let failure = $state<string | null>(null);
  let notice = $state<string | null>(null);

  async function reload() {
    try {
      browsers = await api.listBrowsers();
    } catch (error) {
      failure = messageOf(error);
    }
  }

  async function revoke(browser: BrowserView) {
    busy = browser.id;
    failure = null;
    notice = null;
    try {
      await api.revokeBrowser(browser.id);
      notice = `« ${browser.browser} » est révoqué : il devra être appairé de nouveau.`;
      await reload();
    } catch (error) {
      failure = messageOf(error);
    } finally {
      busy = null;
    }
  }

  onMount(reload);
</script>

<div class="browsers">
  <h2>Navigateurs</h2>
  <p class="muted small">
    L'extension ligrivsstore pour Chrome et Edge rejoint l'application par un canal réservé à votre compte Windows,
    puis chiffre chaque échange. Pour appairer un navigateur : ouvrez les options de l'extension, choisissez
    « Appairer », puis comparez l'empreinte affichée des deux côtés avant de confirmer ici.
  </p>
  {#if failure}<p class="error" role="alert">{failure}</p>{/if}
  {#if notice}<p class="note small" role="status">{notice}</p>{/if}
  {#if browsers === null}
    <p class="muted">Chargement…</p>
  {:else if browsers.length === 0}
    <p class="muted">Aucun navigateur appairé.</p>
  {:else}
    <ul class="backup-list">
      {#each browsers as browser (browser.id)}
        <li>
          <div>
            <strong>{browser.browser}</strong>
            <span class="muted small">
              · appairé le {formatDate(browser.paired)} · dernière liaison : {since(browser.lastSeen)}
            </span>
            <div class="fingerprint small" aria-label="Empreinte">{browser.fingerprint}</div>
          </div>
          <button type="button" onclick={() => revoke(browser)} disabled={busy !== null}>
            {busy === browser.id ? "Révocation…" : "Révoquer"}
          </button>
        </li>
      {/each}
    </ul>
  {/if}
</div>
