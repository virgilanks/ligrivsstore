<script lang="ts">
  import { onMount } from "svelte";
  import { api, messageOf } from "./api";
  import { formatDate, formatSize } from "./format";
  import type { BackupView } from "./types";

  interface Props {
    onRestored: () => void;
  }
  let { onRestored }: Props = $props();

  let backups = $state<BackupView[]>([]);
  let loaded = $state(false);
  let confirm = $state<string | null>(null);
  let busy = $state(false);
  let failure = $state<string | null>(null);
  let notice = $state<string | null>(null);

  async function load() {
    try {
      backups = await api.listBackups();
    } catch (error) {
      failure = messageOf(error);
    } finally {
      loaded = true;
    }
  }

  async function restore(id: string) {
    busy = true;
    failure = null;
    notice = null;
    try {
      const report = await api.restoreBackup(id);
      const parts = [
        `${report.restored} entrée${report.restored > 1 ? "s" : ""} rétablie${report.restored > 1 ? "s" : ""}`,
        `${report.recreated} recréée${report.recreated > 1 ? "s" : ""}`,
      ];
      if (report.skipped > 0) parts.push(`${report.skipped} écartée${report.skipped > 1 ? "s" : ""}`);
      notice = `Restauration faite : ${parts.join(", ")}.`;
      confirm = null;
      onRestored();
      await load();
    } catch (error) {
      failure = messageOf(error);
    } finally {
      busy = false;
    }
  }

  onMount(load);
</script>

<div class="backups">
  <h2>Sauvegardes</h2>
  <p class="muted small">
    À chaque enregistrement, la version précédente du coffre est gardée, chiffrée comme lui : les 10 plus récentes
    sont conservées sur ce PC. Restaurer une sauvegarde remet ses entrées dans leur état d'alors ; la version
    remplacée de chaque entrée reste dans son historique, les entrées créées depuis sont conservées, et la
    restauration se propage à vos autres PC. Elle peut elle-même être annulée en restaurant la sauvegarde qu'elle
    crée.
  </p>
  {#if failure}<p class="error" role="alert">{failure}</p>{/if}
  {#if notice}<p class="note small" role="status">{notice}</p>{/if}
  {#if loaded && backups.length === 0}
    <p class="muted">Aucune sauvegarde pour l'instant : elles apparaissent après les premières modifications.</p>
  {:else}
    <ul class="backup-list">
      {#each backups as backup (backup.id)}
        <li>
          <span>
            Version remplacée le {formatDate(backup.replaced)}
            <span class="muted small"> · {formatSize(backup.size)}</span>
          </span>
          {#if confirm === backup.id}
            <span class="row">
              <span class="small">Restaurer cette version ?</span>
              <button type="button" class="small-button" onclick={() => (confirm = null)} disabled={busy}>Non</button>
              <button type="button" class="small-button primary" onclick={() => restore(backup.id)} disabled={busy}>
                {busy ? "Restauration…" : "Oui, restaurer"}
              </button>
            </span>
          {:else}
            <button type="button" class="small-button" onclick={() => (confirm = backup.id)} disabled={busy}>Restaurer…</button>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</div>
