<script lang="ts">
  import { api, messageOf } from "./api";
  import type { EntryView } from "./types";

  interface Props {
    entry: EntryView;
    onEdit: () => void;
    onDeleted: () => void;
  }
  let { entry, onEdit, onDeleted }: Props = $props();

  let revealed = $state<string | null>(null);
  let confirmDelete = $state(false);
  let busy = $state(false);
  let failure = $state<string | null>(null);

  // Nouvelle fiche : le mot de passe affiché pour la précédente est oublié.
  $effect(() => {
    void entry.id;
    revealed = null;
    confirmDelete = false;
    failure = null;
  });

  async function toggleReveal() {
    if (revealed !== null) {
      revealed = null;
      return;
    }
    try {
      revealed = await api.revealPassword(entry.id);
    } catch (error) {
      failure = messageOf(error);
    }
  }

  async function remove() {
    busy = true;
    failure = null;
    try {
      await api.deleteEntry(entry.id);
      onDeleted();
    } catch (error) {
      failure = messageOf(error);
      busy = false;
    }
  }

  function formatDate(iso: string | null): string {
    if (!iso) return "—";
    const date = new Date(iso);
    return Number.isNaN(date.getTime())
      ? iso
      : date.toLocaleString("fr-FR", { dateStyle: "long", timeStyle: "short" });
  }
</script>

<article class="detail">
  <h2>{entry.title}</h2>
  <dl>
    <dt>Adresse</dt>
    <dd>{entry.url || "—"}</dd>
    <dt>Identifiant</dt>
    <dd><span class="selectable">{entry.username || "—"}</span></dd>
    <dt>Mot de passe</dt>
    <dd>
      {#if !entry.hasPassword}
        —
      {:else}
        <span class="row">
          {#if revealed !== null}
            <code class="selectable">{revealed}</code>
          {:else}
            <span aria-label="mot de passe masqué">••••••••••••</span>
          {/if}
          <button type="button" class="small-button" onclick={toggleReveal}>
            {revealed !== null ? "Masquer" : "Afficher"}
          </button>
        </span>
      {/if}
    </dd>
    <dt>Notes</dt>
    <dd class="notes">{entry.notes || "—"}</dd>
    <dt>Modifiée le</dt>
    <dd>{formatDate(entry.modified)}</dd>
    <dt>Versions antérieures</dt>
    <dd>{entry.historyLen}</dd>
  </dl>

  {#if failure}<p class="error" role="alert">{failure}</p>{/if}

  <div class="actions">
    {#if confirmDelete}
      <span>Supprimer « {entry.title} » ?</span>
      <button type="button" onclick={() => (confirmDelete = false)} disabled={busy}>Non</button>
      <button type="button" class="danger" onclick={remove} disabled={busy}>
        {busy ? "Suppression…" : "Oui, supprimer"}
      </button>
    {:else}
      <button type="button" class="danger-outline" onclick={() => (confirmDelete = true)}>Supprimer</button>
      <button type="button" class="primary" onclick={onEdit}>Modifier</button>
    {/if}
  </div>
</article>
