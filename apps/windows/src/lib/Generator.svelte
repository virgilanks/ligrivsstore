<script lang="ts">
  import { onMount } from "svelte";
  import { api, messageOf } from "./api";
  import type { GeneratorOptions } from "./types";

  interface Props {
    onUse: (password: string) => void;
    onClose: () => void;
  }
  let { onUse, onClose }: Props = $props();

  let options = $state<GeneratorOptions>({
    length: 20,
    lowercase: true,
    uppercase: true,
    digits: true,
    symbols: true,
    excludeAmbiguous: false,
  });
  let value = $state("");
  let entropy = $state(0);
  let failure = $state<string | null>(null);

  let anyFamily = $derived(options.lowercase || options.uppercase || options.digits || options.symbols);

  async function regenerate() {
    failure = null;
    if (!anyFamily) {
      value = "";
      failure = "Choisissez au moins une famille de caractères.";
      return;
    }
    try {
      const generated = await api.generatePassword($state.snapshot(options));
      value = generated.password;
      entropy = Math.round(generated.entropyBits);
    } catch (error) {
      failure = messageOf(error);
    }
  }

  onMount(regenerate);
</script>

<div class="generator" role="group" aria-label="Générateur de mots de passe">
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
  {#if value}
    <p class="generated"><code>{value}</code></p>
    <p class="muted small">Environ {entropy} bits d'entropie.</p>
  {/if}
  {#if failure}<p class="error small">{failure}</p>{/if}
  <div class="actions">
    <button type="button" onclick={onClose}>Fermer</button>
    <button type="button" onclick={regenerate}>Autre mot de passe</button>
    <button type="button" class="primary" disabled={!value} onclick={() => onUse(value)}>Utiliser</button>
  </div>
</div>
