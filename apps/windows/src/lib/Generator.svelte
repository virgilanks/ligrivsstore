<script lang="ts">
  import { onMount } from "svelte";
  import { api, messageOf } from "./api";
  import type { GeneratorOptions, PassphraseOptions } from "./types";

  interface Props {
    onUse: (password: string) => void;
    onClose: () => void;
  }
  let { onUse, onClose }: Props = $props();

  type Kind = "mot" | "phrase";

  let kind = $state<Kind>("mot");
  let options = $state<GeneratorOptions>({
    length: 20,
    lowercase: true,
    uppercase: true,
    digits: true,
    symbols: true,
    excludeAmbiguous: false,
  });
  let phrase = $state<PassphraseOptions>({
    words: 6,
    separator: "-",
    capitalize: false,
    digit: false,
  });
  let value = $state("");
  let entropy = $state(0);
  let failure = $state<string | null>(null);

  let anyFamily = $derived(options.lowercase || options.uppercase || options.digits || options.symbols);

  async function regenerate() {
    failure = null;
    if (kind === "mot" && !anyFamily) {
      value = "";
      failure = "Choisissez au moins une famille de caractères.";
      return;
    }
    try {
      const generated =
        kind === "mot"
          ? await api.generatePassword($state.snapshot(options))
          : await api.generatePassphrase($state.snapshot(phrase));
      value = generated.password;
      entropy = Math.round(generated.entropyBits);
    } catch (error) {
      failure = messageOf(error);
    }
  }

  function switchTo(next: Kind) {
    kind = next;
    void regenerate();
  }

  onMount(regenerate);
</script>

<div class="generator" role="group" aria-label="Générateur">
  <div class="segmented" role="radiogroup" aria-label="Type">
    <label class:current={kind === "mot"}>
      <input type="radio" name="genre" checked={kind === "mot"} onchange={() => switchTo("mot")} /> Mot de passe
    </label>
    <label class:current={kind === "phrase"}>
      <input type="radio" name="genre" checked={kind === "phrase"} onchange={() => switchTo("phrase")} /> Phrase de passe
    </label>
  </div>

  {#if kind === "mot"}
    <div class="row">
      <label for="longueur">Longueur</label>
      <input id="longueur" type="range" min="8" max="64" bind:value={options.length} onchange={regenerate} />
      <span class="value">{options.length}</span>
    </div>
    <div class="checks">
      <label><input type="checkbox" bind:checked={options.lowercase} onchange={regenerate} /> minuscules</label>
      <label><input type="checkbox" bind:checked={options.uppercase} onchange={regenerate} /> majuscules</label>
      <label><input type="checkbox" bind:checked={options.digits} onchange={regenerate} /> chiffres</label>
      <label><input type="checkbox" bind:checked={options.symbols} onchange={regenerate} /> symboles</label>
      <label><input type="checkbox" bind:checked={options.excludeAmbiguous} onchange={regenerate} /> sans caractères ambigus</label>
    </div>
  {:else}
    <div class="row">
      <label for="mots">Mots</label>
      <input id="mots" type="range" min="4" max="12" bind:value={phrase.words} onchange={regenerate} />
      <span class="value">{phrase.words}</span>
    </div>
    <div class="checks">
      <label class="inline">
        Séparateur
        <select bind:value={phrase.separator} onchange={regenerate}>
          <option value="-">tiret</option>
          <option value=" ">espace</option>
          <option value=".">point</option>
          <option value="_">soulignement</option>
        </select>
      </label>
      <label><input type="checkbox" bind:checked={phrase.capitalize} onchange={regenerate} /> majuscules initiales</label>
      <label><input type="checkbox" bind:checked={phrase.digit} onchange={regenerate} /> un chiffre</label>
    </div>
    <p class="muted small">Mots anglais de la liste de l'EFF : faciles à taper et à retenir.</p>
  {/if}

  {#if value}
    <p class="generated"><code>{value}</code></p>
    <p class="muted small">Environ {entropy} bits d'entropie.</p>
  {/if}
  {#if failure}<p class="error small">{failure}</p>{/if}
  <div class="actions">
    <button type="button" onclick={onClose}>Fermer</button>
    <button type="button" onclick={regenerate}>{kind === "mot" ? "Autre mot de passe" : "Autre phrase"}</button>
    <button type="button" class="primary" disabled={!value} onclick={() => onUse(value)}>Utiliser</button>
  </div>
</div>
