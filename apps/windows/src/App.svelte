<script lang="ts">
  import { onMount } from "svelte";
  import { api, messageOf } from "./lib/api";
  import type { Status } from "./lib/types";
  import Welcome from "./lib/Welcome.svelte";
  import CreateVault from "./lib/CreateVault.svelte";
  import Unlock from "./lib/Unlock.svelte";
  import VaultView from "./lib/VaultView.svelte";

  type Screen = "chargement" | "bienvenue" | "creation" | "deverrouillage" | "coffre";

  let screen = $state<Screen>("chargement");
  let status = $state<Status | null>(null);
  let vaultToOpen = $state<string | null>(null);
  let failure = $state<string | null>(null);

  function show(next: Status) {
    status = next;
    if (next.unlocked) {
      screen = "coffre";
    } else if (next.vaultPath) {
      vaultToOpen = next.vaultPath;
      screen = "deverrouillage";
    } else {
      screen = "bienvenue";
    }
  }

  async function changeVault() {
    try {
      const next = await api.forgetVault();
      status = next;
      vaultToOpen = null;
      screen = "bienvenue";
    } catch (error) {
      failure = messageOf(error);
    }
  }

  onMount(async () => {
    try {
      show(await api.status());
    } catch (error) {
      failure = messageOf(error);
    }
  });
</script>

<main>
  {#if failure}
    <section class="panel" role="alert">
      <h1>ligrivsstore</h1>
      <p class="error">{failure}</p>
    </section>
  {:else if screen === "chargement"}
    <p class="muted centered">Chargement…</p>
  {:else if screen === "bienvenue"}
    <Welcome
      onCreate={() => (screen = "creation")}
      onOpen={(path) => {
        vaultToOpen = path;
        screen = "deverrouillage";
      }}
    />
  {:else if screen === "creation"}
    <CreateVault onCreated={show} onCancel={() => (screen = "bienvenue")} />
  {:else if screen === "deverrouillage" && vaultToOpen}
    <Unlock
      path={vaultToOpen}
      keyfilePath={status?.vaultPath === vaultToOpen ? (status?.keyfilePath ?? null) : null}
      onUnlocked={show}
      onChangeVault={changeVault}
    />
  {:else if screen === "coffre" && status}
    <VaultView {status} onLocked={show} onStatus={(next) => (status = next)} />
  {/if}
</main>
