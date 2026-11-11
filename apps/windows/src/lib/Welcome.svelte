<script lang="ts">
  import { messageOf } from "./api";
  import { chooseVaultToOpen } from "./files";

  interface Props {
    onCreate: () => void;
    onOpen: (path: string) => void;
  }
  let { onCreate, onOpen }: Props = $props();
  let failure = $state<string | null>(null);

  async function openExisting() {
    failure = null;
    try {
      const path = await chooseVaultToOpen();
      if (path) onOpen(path);
    } catch (error) {
      failure = messageOf(error);
    }
  }
</script>

<section class="panel narrow">
  <h1>ligrivsstore</h1>
  <p class="lead">Vos mots de passe, chiffrés sur ce PC et synchronisés avec votre serveur.</p>
  <div class="choices">
    <button type="button" class="primary" onclick={onCreate}>Créer un coffre</button>
    <button type="button" onclick={openExisting}>Ouvrir un coffre existant…</button>
  </div>
  <p class="muted small">
    Les coffres sont au format ouvert KDBX : KeePassXC, KeePassDX et KeePassium savent aussi les lire.
  </p>
  {#if failure}<p class="error" role="alert">{failure}</p>{/if}
</section>
