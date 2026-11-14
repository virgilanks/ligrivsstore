// Mise en forme des dates et des tailles, en français.

/** Date et heure lisibles, ou « — ». */
export function formatDate(iso: string | null): string {
  if (!iso) return "—";
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? iso
    : date.toLocaleString("fr-FR", { dateStyle: "long", timeStyle: "short" });
}

/** Durée écoulée depuis `iso`, en mots (« à l'instant », « il y a 5 min »). */
export function since(iso: string | null, now: number = Date.now()): string {
  if (!iso) return "jamais";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const seconds = Math.max(0, Math.round((now - then) / 1000));
  if (seconds < 60) return "à l'instant";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `il y a ${minutes} min`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `il y a ${hours} h`;
  return `le ${formatDate(iso)}`;
}

/** Taille lisible (« 12 Ko »). */
export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} octets`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} Ko`;
  return `${(bytes / (1024 * 1024)).toFixed(1).replace(".", ",")} Mo`;
}
