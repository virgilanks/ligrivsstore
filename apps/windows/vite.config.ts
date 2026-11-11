import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// Interface de l'application Windows. Tauri sert le dossier dist/ par son
// protocole interne : aucun contenu distant n'est chargé.
export default defineConfig({
  plugins: [svelte()],
  clearScreen: false,
  server: {
    host: "127.0.0.1",
    port: 1420,
    strictPort: true,
  },
  build: {
    // WebView2 suit Chromium (canal stable, mis à jour par Windows).
    target: "chrome120",
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
  },
});
