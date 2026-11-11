<script lang="ts">
  import { onMount } from "svelte";
  import { api, messageOf } from "./api";
  import EntryDetail from "./EntryDetail.svelte";
  import EntryEditor from "./EntryEditor.svelte";
  import type { EntryRow, EntryView, Status } from "./types";

  interface Props {
    status: Status;
    onLocked: (status: Status) => void;
    onStatus: (status: Status) => void;
  }
  let { status, onLocked, onStatus }: Props = $props();

  type Mode = "vide" | "fiche" | "modification" | "creation";

  let query = $state("");
  let rows = $state<EntryRow[]>([]);
  let selected = $state<EntryView | null>(null);
  let mode = $state<Mode>("vide");
  let newForm = $state(0);
  let failure = $state<string | null>(null);
  let locking = $state(false);

  async function refresh() {
    try {
      rows = await api.listEntries(query);
      onStatus(await api.status());
    } catch (error) {
      failure = messageOf(error);
    }
  }

  async function select(id: string) {
    failure = null;
    try {
      selected = await api.getEntry(id);
      mode = "fiche";
    } catch (error) {
      failure = messageOf(error);
    }
  }

  async function saved(id: string) {
    await refresh();
    await select(id);
  }

  async function deleted() {
    selected = null;
    mode = "vide";
    await refresh();
  }

  async function lock() {
    locking = true;
    try {
      onLocked(await api.lockVault());
    } catch (error) {
      failure = messageOf(error);
      locking = false;
    }
  }

  async function retrySave() {
    try {
      await api.retrySave();
      await refresh();
    } catch (error) {
      failure = messageOf(error);
    }
  }

  // Recherche, après une courte pause de saisie.
  let timer: ReturnType<typeof setTimeout> | undefined;
  $effect(() => {
    void query;
    clearTimeout(timer);
    timer = setTimeout(refresh, 150);
    return () => clearTimeout(timer);
  });

  onMount(refresh);
</script>

<div class="vault">
  <header class="toolbar">
    <div class="heading">
      <h1>{status.vaultName ?? "Coffre"}</h1>
      <p class="muted small" title={status.vaultPath ?? ""}>
        {status.entryCount} entrée{status.entryCount > 1 ? "s" : ""} · {status.vaultPath}
      </p>
    </div>
    <div class="actions">
      <button
        type="button"
        class="primary"
        onclick={() => {
          selected = null;
          mode = "creation";
          newForm += 1;
        }}>Nouvelle entrée</button
      >
      <button type="button" onclick={lock} disabled={locking}>Verrouiller</button>
    </div>
  </header>

  {#if status.unsaved}
    <div class="banner" role="alert">
      Des modifications n'ont pas pu être enregistrées sur le disque.
      <button type="button" onclick={retrySave}>Réessayer</button>
    </div>
  {/if}
  {#if failure}<p class="error" role="alert">{failure}</p>{/if}

  <div class="columns">
    <nav class="list" aria-label="Entrées du coffre">
      <input type="search" placeholder="Rechercher" aria-label="Rechercher une entrée" bind:value={query} spellcheck="false" />
      {#if rows.length === 0}
        <p class="muted small">{query ? "Aucune entrée ne correspond." : "Aucune entrée pour l'instant."}</p>
      {:else}
        <ul>
          {#each rows as row (row.id)}
            <li>
              <button type="button" class:current={selected?.id === row.id} onclick={() => select(row.id)}>
                <span class="title">{row.title}</span>
                <span class="sub">{row.username || row.url || " "}</span>
              </button>
            </li>
          {/each}
        </ul>
      {/if}
    </nav>

    <section class="pane">
      {#if mode === "creation"}
        <!-- Un nouveau clic sur « Nouvelle entrée » repart d'un formulaire vide. -->
        {#key newForm}
          <EntryEditor entry={null} onSaved={saved} onCancel={() => (mode = "vide")} />
        {/key}
      {:else if mode === "modification" && selected}
        <EntryEditor entry={selected} onSaved={saved} onCancel={() => (mode = "fiche")} />
      {:else if mode === "fiche" && selected}
        <EntryDetail entry={selected} onEdit={() => (mode = "modification")} onDeleted={deleted} />
      {:else}
        <p class="muted centered">Choisissez une entrée, ou créez-en une.</p>
      {/if}
    </section>
  </div>
</div>
