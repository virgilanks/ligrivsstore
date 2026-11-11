<script lang="ts">
  import { onMount } from "svelte";
  import { api, messageOf } from "./api";
  import { chooseExistingKeyfile, chooseNewKeyfilePath, chooseNewVaultPath } from "./files";
  import StrengthMeter from "./StrengthMeter.svelte";
  import type { KeyfileChoice, Status, Strength } from "./types";

  interface Props {
    onCreated: (status: Status) => void;
    onCancel: () => void;
  }
  let { onCreated, onCancel }: Props = $props();

  type KeyfileMode = "generate" | "existing" | "none";

  let name = $state("Coffre");
  let vaultPath = $state("");
  let passphrase = $state("");
  let confirmation = $state("");
  let strength = $state<Strength | null>(null);
  let keyfileMode = $state<KeyfileMode>("generate");
  let newKeyfilePath = $state("");
  let existingKeyfilePath = $state("");
  let busy = $state(false);
  let failure = $state<string | null>(null);

  let mismatch = $derived(confirmation !== "" && confirmation !== passphrase);
  let keyfileReady = $derived(
    keyfileMode === "none" ||
      (keyfileMode === "generate" && newKeyfilePath.trim() !== "") ||
      (keyfileMode === "existing" && existingKeyfilePath.trim() !== ""),
  );
  let ready = $derived(
    !busy &&
      vaultPath.trim() !== "" &&
      strength?.acceptable === true &&
      passphrase === confirmation &&
      keyfileReady,
  );

  onMount(async () => {
    try {
      const paths = await api.defaultPaths();
      vaultPath = paths.vault;
      newKeyfilePath = paths.keyfile;
    } catch (error) {
      failure = messageOf(error);
    }
  });

  // Robustesse estimée par le cœur, après une courte pause de saisie.
  let timer: ReturnType<typeof setTimeout> | undefined;
  $effect(() => {
    const value = passphrase;
    clearTimeout(timer);
    if (value === "") {
      strength = null;
      return;
    }
    timer = setTimeout(async () => {
      try {
        strength = await api.passphraseStrength(value);
      } catch {
        strength = null;
      }
    }, 250);
    return () => clearTimeout(timer);
  });

  async function pickVaultPath() {
    const chosen = await chooseNewVaultPath(vaultPath);
    if (chosen) vaultPath = chosen;
  }

  async function pickNewKeyfile() {
    const chosen = await chooseNewKeyfilePath(newKeyfilePath);
    if (chosen) newKeyfilePath = chosen;
  }

  async function pickExistingKeyfile() {
    const chosen = await chooseExistingKeyfile();
    if (chosen) existingKeyfilePath = chosen;
  }

  function keyfileChoice(): KeyfileChoice {
    switch (keyfileMode) {
      case "generate":
        return { kind: "generate", path: newKeyfilePath.trim() };
      case "existing":
        return { kind: "existing", path: existingKeyfilePath.trim() };
      default:
        return { kind: "none" };
    }
  }

  async function create(event: SubmitEvent) {
    event.preventDefault();
    if (!ready) return;
    busy = true;
    failure = null;
    try {
      const status = await api.createVault({
        path: vaultPath.trim(),
        name: name.trim(),
        passphrase,
        keyfile: keyfileChoice(),
      });
      passphrase = "";
      confirmation = "";
      onCreated(status);
    } catch (error) {
      failure = messageOf(error);
    } finally {
      busy = false;
    }
  }
</script>

<section class="panel">
  <h1>Créer un coffre</h1>
  <form onsubmit={create}>
    <label for="nom">Nom du coffre</label>
    <input id="nom" type="text" bind:value={name} disabled={busy} maxlength="80" />

    <label for="emplacement">Emplacement</label>
    <div class="row">
      <input id="emplacement" type="text" bind:value={vaultPath} disabled={busy} spellcheck="false" />
      <button type="button" onclick={pickVaultPath} disabled={busy}>Changer…</button>
    </div>

    <label for="phrase">Phrase de passe</label>
    <input id="phrase" type="password" autocomplete="new-password" bind:value={passphrase} disabled={busy} />
    <StrengthMeter {strength} />
    <p class="muted small">
      Plusieurs mots sans rapport entre eux, avec des séparateurs, font une phrase solide et facile à retenir.
      Elle ne peut pas être récupérée : notez-la en lieu sûr.
    </p>

    <label for="confirmation">Confirmation</label>
    <input id="confirmation" type="password" autocomplete="new-password" bind:value={confirmation} disabled={busy} />
    {#if mismatch}<p class="error small">Les deux saisies diffèrent.</p>{/if}

    <fieldset disabled={busy}>
      <legend>Fichier clé</legend>
      <label class="option">
        <input type="radio" name="cle" value="generate" bind:group={keyfileMode} />
        Créer un nouveau fichier clé <span class="muted">(recommandé)</span>
      </label>
      {#if keyfileMode === "generate"}
        <div class="row indent">
          <input type="text" aria-label="Emplacement du nouveau fichier clé" bind:value={newKeyfilePath} spellcheck="false" />
          <button type="button" onclick={pickNewKeyfile}>Changer…</button>
        </div>
        <p class="note small indent">
          Gardez une copie de ce fichier à part, par exemple sur une clé USB : sans lui, le coffre ne s'ouvre plus.
          Ne le mettez pas sur le serveur avec le coffre.
        </p>
      {/if}
      <label class="option">
        <input type="radio" name="cle" value="existing" bind:group={keyfileMode} />
        Utiliser un fichier clé existant
      </label>
      {#if keyfileMode === "existing"}
        <div class="row indent">
          <input type="text" aria-label="Fichier clé existant" bind:value={existingKeyfilePath} spellcheck="false" />
          <button type="button" onclick={pickExistingKeyfile}>Choisir…</button>
        </div>
      {/if}
      <label class="option">
        <input type="radio" name="cle" value="none" bind:group={keyfileMode} />
        Phrase de passe seule
      </label>
    </fieldset>

    {#if failure}<p class="error" role="alert">{failure}</p>{/if}

    <div class="actions">
      <button type="button" onclick={onCancel} disabled={busy}>Annuler</button>
      <button type="submit" class="primary" disabled={!ready}>
        {busy ? "Création du coffre…" : "Créer le coffre"}
      </button>
    </div>
    {#if busy}
      <p class="muted small" aria-live="polite">Réglage du chiffrement sur ce PC : environ une seconde.</p>
    {/if}
  </form>
</section>
