<script lang="ts">
  import type { Strength } from "./types";

  interface Props {
    strength: Strength | null;
  }
  let { strength }: Props = $props();
</script>

<div class="strength" aria-live="polite">
  <div class="bar score-{strength?.score ?? 0}" class:empty={!strength}></div>
  <p class="small">
    {#if !strength}
      Robustesse : —
    {:else if strength.tooShort}
      Trop courte : 12 caractères au moins.
    {:else}
      Robustesse : {strength.label}{strength.acceptable ? "" : " — choisissez une phrase plus longue ou moins prévisible"}.
    {/if}
  </p>
</div>
