<script lang="ts">
  import { api, AppError, messageOf } from "./api";
  import { chooseExistingKeyfile } from "./files";
  import { focusOnMount } from "./focus";
  import type { Status } from "./types";

  interface Props {
    path: string;
    keyfilePath: string | null;
    /** Motif du dernier verrouillage automatique. */
    lockMessage: string | null;
    onUnlocked: (status: Status) => void;
    onChangeVault: () => void;
  }
  let { path, keyfilePath, lockMessage, onUnlocked, onChangeVault }: Props = $props();

  let passphrase = $state("");
  let keyfile = $state("");
  let busy = $state(false);
  let failure = $state<string | null>(null);

  $effect(() => {
    keyfile = keyfilePath ?? "";
  });

  async function chooseKeyfile() {
    const chosen = await chooseExistingKeyfile();
    if (chosen) keyfile = chosen;
  }

  async function unlock(event: SubmitEvent) {
    event.preventDefault();
    busy = true;
    failure = null;
    try {
      const status = await api.openVault({
        path,
        passphrase,
        keyfilePath: keyfile.trim() === "" ? null : keyfile.trim(),
      });
      passphrase = "";
      onUnlocked(status);
    } catch (error) {
      failure =
        error instanceof AppError && error.code === "cle_incorrecte"
          ? "Phrase de passe ou fichier clé incorrect."
          : messageOf(error);
    } finally {
      busy = false;
    }
  }
</script>

<section class="panel narrow">
  <h1>Déverrouiller le coffre</h1>
  <p class="path" title={path}>{path}</p>
  {#if lockMessage}<p class="note small" role="status">{lockMessage}</p>{/if}
  <form onsubmit={unlock}>
    <label for="phrase">Phrase de passe</label>
    <input id="phrase" type="password" autocomplete="off" bind:value={passphrase} disabled={busy} {@attach focusOnMount} />

    <label for="cle">Fichier clé <span class="muted">(s'il y en a un)</span></label>
    <div class="row">
      <input id="cle" type="text" bind:value={keyfile} disabled={busy} placeholder="Aucun" spellcheck="false" />
      <button type="button" onclick={chooseKeyfile} disabled={busy}>Choisir…</button>
    </div>

    {#if failure}<p class="error" role="alert">{failure}</p>{/if}

    <div class="actions">
      <button type="button" class="link" onclick={onChangeVault} disabled={busy}>Changer de coffre</button>
      <button type="submit" class="primary" disabled={busy || (passphrase === "" && keyfile.trim() === "")}>
        {busy ? "Ouverture…" : "Déverrouiller"}
      </button>
    </div>
  </form>
</section>
