// Construction de l'extension (dist/) ou des essais (dist-essais/), avec
// esbuild. Aucun code distant : tout est empaqueté et servi par l'extension.
import { build } from "esbuild";
import { cpSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";

const essais = process.argv.includes("--essais");
// Variante pour l'essai de bout en bout automatisé : la permission « tabs »
// remplace le clic sur l'icône de l'extension (activeTab), qu'un automate ne
// peut pas faire. Jamais livrée.
const bout = process.argv.includes("--bout-en-bout");
const sortie = bout ? "dist-bout-en-bout" : "dist";

if (essais) {
  rmSync("dist-essais", { recursive: true, force: true });
  const entryPoints = readdirSync("tests")
    .filter((name) => name.endsWith(".test.ts"))
    .map((name) => `tests/${name}`);
  await build({
    entryPoints,
    outdir: "dist-essais",
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node22",
    outExtension: { ".js": ".mjs" },
    logLevel: "warning",
  });
} else {
  rmSync(sortie, { recursive: true, force: true });
  mkdirSync(sortie, { recursive: true });
  cpSync("static", sortie, { recursive: true });
  if (bout) {
    const chemin = `${sortie}/manifest.json`;
    const manifeste = JSON.parse(readFileSync(chemin, "utf8"));
    manifeste.permissions.push("tabs");
    writeFileSync(chemin, JSON.stringify(manifeste, null, 2));
  }
  await build({
    entryPoints: ["src/background.ts", "src/popup.ts", "src/options.ts"],
    outdir: sortie,
    bundle: true,
    format: "esm",
    target: "chrome133",
    minify: false,
    sourcemap: false,
    legalComments: "none",
    logLevel: "warning",
  });
}
