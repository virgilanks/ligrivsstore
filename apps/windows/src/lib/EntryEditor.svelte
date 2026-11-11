<script lang="ts">
  import { api, messageOf } from "./api";
  import { focusOnMount } from "./focus";
  import Generator from "./Generator.svelte";
  import type { EntryView } from "./types";

  interface Props {
    entry: EntryView | null;
    onSaved: (id: string) => void;
    onCancel: () => void;
  }
  let { entry, onSaved, onCancel }: Props = $props();

  let title = $state("");
  let url = $state("");
  let username = $state("");
  let password = $state("");
  let notes = $state("");
  let showPassword = $state(false);
  let showGenerator = $state(false);
  let busy = $state(false);
  let failure = $state<string | null>(null);

  $effect(() => {
    title = entry?.title ?? "";
    url = entry?.url ?? "";
    username = entry?.username ?? "";
    notes = entry?.notes ?? "";
    password = "";
  });

  async function save(event: SubmitEvent) {
    event.preventDefault();
    if (title.trim() === "") {
      failure = "Le titre est obligatoire.";
      return;
    }
    busy = true;
    failure = null;
    try {
      const id = await api.saveEntry({
        id: entry?.id ?? null,
        title,
        url,
        username,
        // Champ vide en modification : le mot de passe actuel est conservé.
        password: entry && password === "" ? null : password,
        notes,
      });
      password = "";
      onSaved(id);
    } catch (error) {
      failure = messageOf(error);
    } finally {
      busy = false;
    }
  }
</script>

<form class="editor" onsubmit={save}>
  <h2>{entry ? "Modifier l'entrée" : "Nouvelle entrée"}</h2>

  <label for="titre">Titre</label>
  <input id="titre" type="text" bind:value={title} disabled={busy} required maxlength="200" {@attach focusOnMount} />

  <label for="adresse">Adresse du site, serveur ou application</label>
  <input id="adresse" type="text" bind:value={url} disabled={busy} placeholder="https://" spellcheck="false" />

  <label for="identifiant">Identifiant ou e-mail</label>
  <input id="identifiant" type="text" bind:value={username} disabled={busy} autocomplete="off" spellcheck="false" />

  <label for="motdepasse">Mot de passe</label>
  <div class="row">
    <input
      id="motdepasse"
      type={showPassword ? "text" : "password"}
      bind:value={password}
      disabled={busy}
      autocomplete="off"
      spellcheck="false"
      placeholder={entry?.hasPassword ? "Laisser vide pour garder l'actuel" : ""}
    />
    <button type="button" onclick={() => (showPassword = !showPassword)} disabled={busy}>
      {showPassword ? "Masquer" : "Afficher"}
    </button>
    <button type="button" onclick={() => (showGenerator = !showGenerator)} disabled={busy}>Générer…</button>
  </div>
  {#if showGenerator}
    <Generator
      onUse={(generated) => {
        password = generated;
        showGenerator = false;
      }}
      onClose={() => (showGenerator = false)}
    />
  {/if}

  <label for="notes">Notes</label>
  <textarea id="notes" rows="4" bind:value={notes} disabled={busy}></textarea>

  {#if failure}<p class="error" role="alert">{failure}</p>{/if}

  <div class="actions">
    <button type="button" onclick={onCancel} disabled={busy}>Annuler</button>
    <button type="submit" class="primary" disabled={busy}>{busy ? "Enregistrement…" : "Enregistrer"}</button>
  </div>
</form>
