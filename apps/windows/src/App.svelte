<script lang="ts">
  import { onMount } from "svelte";
  import { api, messageOf } from "./lib/api";
  import type { Activity, Status } from "./lib/types";
  import Welcome from "./lib/Welcome.svelte";
  import CreateVault from "./lib/CreateVault.svelte";
  import InstallFromServer from "./lib/InstallFromServer.svelte";
  import Unlock from "./lib/Unlock.svelte";
  import VaultView from "./lib/VaultView.svelte";
  import PairingDialog from "./lib/PairingDialog.svelte";

  type Screen = "chargement" | "bienvenue" | "creation" | "installation" | "deverrouillage" | "coffre";

  /** Relecture de l'état observable (verrouillage, synchronisation). */
  const POLL_MS = 2000;
  /** Une activité dans la fenêtre est signalée au plus une fois par période. */
  const PING_MS = 20_000;

  let screen = $state<Screen>("chargement");
  let status = $state<Status | null>(null);
  let activity = $state<Activity | null>(null);
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

  async function poll() {
    try {
      activity = await api.activity();
      // Verrouillé hors de l'interface (inactivité, session Windows, veille).
      if (screen === "coffre" && !activity.unlocked) {
        show(await api.status());
      }
    } catch {
      // Un échec isolé n'interrompt pas la relecture suivante.
    }
  }

  let lastPing = 0;
  function onUserActivity() {
    const now = Date.now();
    if (screen === "coffre" && now - lastPing > PING_MS) {
      lastPing = now;
      void api.pingActivity().catch(() => {});
    }
  }

  onMount(() => {
    void (async () => {
      try {
        show(await api.status());
        activity = await api.activity();
      } catch (error) {
        failure = messageOf(error);
      }
    })();
    const timer = setInterval(poll, POLL_MS);
    return () => clearInterval(timer);
  });
</script>

<svelte:window onkeydown={onUserActivity} onpointerdown={onUserActivity} />

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
      onInstall={() => (screen = "installation")}
      onOpen={(path) => {
        vaultToOpen = path;
        screen = "deverrouillage";
      }}
    />
  {:else if screen === "creation"}
    <CreateVault onCreated={show} onCancel={() => (screen = "bienvenue")} />
  {:else if screen === "installation"}
    <InstallFromServer onInstalled={show} onCancel={() => (screen = "bienvenue")} />
  {:else if screen === "deverrouillage" && vaultToOpen}
    <Unlock
      path={vaultToOpen}
      keyfilePath={status?.vaultPath === vaultToOpen ? (status?.keyfilePath ?? null) : null}
      lockMessage={activity?.lockMessage ?? null}
      onUnlocked={show}
      onChangeVault={changeVault}
    />
  {:else if screen === "coffre" && status}
    <VaultView {status} {activity} onLocked={show} onStatus={(next) => (status = next)} />
  {/if}
  <!-- Demande d'appairage d'un navigateur : au-dessus de tout écran, coffre
       verrouillé ou non. -->
  {#if activity && activity.pairingRequests > 0}
    <PairingDialog count={activity.pairingRequests} />
  {/if}
</main>
