/** Small display helpers shared by pages. */

export function relTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.round(diff / 60_000);
  if (m < 1) return "just now";
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.round(h / 24)} d ago`;
}

export function duration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "—";
  if (ms < 1000) return `${ms} ms`;
  const s = Math.round(ms / 1000);
  if (s < 90) return `${s} s`;
  const m = Math.floor(s / 60);
  return `${m} min ${s - m * 60} s`;
}

export function scanTypeLabel(t: string): string {
  const map: Record<string, string> = {
    quick: "Quick",
    full_web: "Full web",
    full_web_source: "Full web + source",
    api: "API",
    mobile: "Mobile",
    container: "Container",
    full_spectrum: "Full spectrum",
  };
  return map[t] ?? t.replaceAll("_", " ");
}

export function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
