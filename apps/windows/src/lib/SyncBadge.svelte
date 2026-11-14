<script lang="ts">
  import { since } from "./format";
  import type { SyncStatusView } from "./types";

  interface Props {
    sync: SyncStatusView;
    onOpen: () => void;
  }
  let { sync, onOpen }: Props = $props();

  const LABELS: Record<SyncStatusView["state"], string> = {
    non_configuree: "Synchronisation non réglée",
    en_attente: "Synchronisation…",
    a_envoyer: "Modifications à envoyer",
    en_cours: "Synchronisation…",
    a_jour: "À jour",
    hors_ligne: "Hors ligne",
    suspendue: "Synchronisation suspendue",
    erreur: "Synchronisation en échec",
  };

  let detail = $derived(
    sync.state === "a_jour"
      ? since(sync.lastSuccess)
      : sync.state === "hors_ligne"
        ? "nouvel essai plus tard"
        : null,
  );
</script>

<button type="button" class="badge state-{sync.state}" onclick={onOpen} title={sync.message ?? LABELS[sync.state]}>
  <span class="dot" aria-hidden="true"></span>
  {LABELS[sync.state]}{#if detail}<span class="muted"> · {detail}</span>{/if}
</button>
