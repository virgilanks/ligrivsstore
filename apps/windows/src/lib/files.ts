// Boîtes de dialogue de fichiers de Windows (greffon dialog de Tauri).

import { open, save } from "@tauri-apps/plugin-dialog";

const COFFRES = [{ name: "Coffres KeePass (KDBX)", extensions: ["kdbx"] }];
const CLES = [
  { name: "Fichiers clés", extensions: ["keyx", "key"] },
  { name: "Tous les fichiers", extensions: ["*"] },
];

export async function chooseVaultToOpen(): Promise<string | null> {
  const path = await open({ title: "Ouvrir un coffre", multiple: false, directory: false, filters: COFFRES });
  return typeof path === "string" ? path : null;
}

export async function chooseNewVaultPath(defaultPath: string): Promise<string | null> {
  return await save({ title: "Emplacement du nouveau coffre", defaultPath, filters: COFFRES });
}

export async function chooseExistingKeyfile(): Promise<string | null> {
  const path = await open({ title: "Choisir le fichier clé", multiple: false, directory: false, filters: CLES });
  return typeof path === "string" ? path : null;
}

export async function chooseNewKeyfilePath(defaultPath: string): Promise<string | null> {
  return await save({ title: "Emplacement du nouveau fichier clé", defaultPath, filters: CLES });
}
