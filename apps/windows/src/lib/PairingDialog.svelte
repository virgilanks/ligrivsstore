<script lang="ts">
  import { tick } from "svelte";
  import { focusOnMount } from "./focus";
  import { api, messageOf } from "./api";
  import type { PairingRequestView } from "./types";

  interface Props {
    /** Nombre de demandes en attente, relu avec l'état de l'application. */
    count: number;
  }
  let { count }: Props = $props();

  let requests = $state<PairingRequestView[]>([]);
  let busy = $state(false);
  let failure = $state<string | null>(null);

  let current = $derived(requests[0] ?? null);
  /** Élément qui avait le focus avant la demande (le champ de la phrase de
   * passe, par exemple) : il le retrouve quand la demande est tranchée. */
  let returnFocus: HTMLElement | null = null;

  async function reload() {
    try {
      const next = await api.pendingPairings();
      const opening = requests.length === 0 && next.length > 0;
      const closing = requests.length > 0 && next.length === 0;
      // Relevé avant l'affichage de la demande, qui prend le focus.
      if (opening && document.activeElement instanceof HTMLElement && document.activeElement !== document.body) {
        returnFocus = document.activeElement;
      }
      requests = next;
      if (closing) {
        await tick();
        if (returnFocus?.isConnected) returnFocus.focus();
        returnFocus = null;
      }
    } catch (error) {
      failure = messageOf(error);
    }
  }

  // Relue à chaque changement du nombre de demandes.
  $effect(() => {
    void count;
    void reload();
  });

  async function decide(confirm: boolean) {
    if (!current) return;
    busy = true;
    failure = null;
    try {
      await api.decidePairing(current.id, confirm);
    } catch (error) {
      failure = messageOf(error);
    } finally {
      busy = false;
      await reload();
    }
  }
</script>

{#if current}
  <div class="overlay">
    <div class="dialog" role="alertdialog" aria-modal="true" aria-labelledby="appairage-titre" aria-describedby="appairage-texte">
      <h2 id="appairage-titre">Appairer « {current.browser} » ?</h2>
      <p id="appairage-texte">
        Une extension ligrivsstore demande à rejoindre l'application. Vérifiez que l'empreinte affichée par l'extension
        est exactement celle-ci, chiffre par chiffre :
      </p>
      <p class="fingerprint" aria-label="Empreinte">{current.fingerprint}</p>
      <p class="muted small">
        Si elle diffère, ou si vous n'avez rien demandé, refusez. Une fois appairé, le navigateur voit les titres et
        les identifiants des entrées du site ouvert ; vous pourrez le révoquer dans l'onglet « Navigateurs ».
      </p>
      {#if failure}<p class="error" role="alert">{failure}</p>{/if}
      <div class="actions">
        <button type="button" onclick={() => decide(false)} disabled={busy} {@attach focusOnMount}>Refuser</button>
        <button type="button" class="primary" onclick={() => decide(true)} disabled={busy}>Confirmer l'appairage</button>
      </div>
    </div>
  </div>
{/if}
