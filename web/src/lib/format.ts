const dateTime = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
});
const timeOnly = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" });
const shortThisYear = new Intl.DateTimeFormat(undefined, {
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
});
const shortOtherYear = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "numeric",
});
const dateOnly = new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric" });
const compact = new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 });

export const formatDateTime = (iso: string | null): string =>
  iso ? dateTime.format(new Date(iso)) : "—";

/** Compact form for table cells: "Nov 8, 01:46 PM" (date only for other years). */
export function formatShort(iso: string | null): string {
  if (!iso) return "—";
  const date = new Date(iso);
  return date.getFullYear() === new Date().getFullYear()
    ? shortThisYear.format(date)
    : shortOtherYear.format(date);
}

export const formatDate = (iso: string | null): string =>
  iso ? dateOnly.format(new Date(iso)) : "—";

export const formatTime = (iso: string | null): string =>
  iso ? timeOnly.format(new Date(iso)) : "";

/** 1,284 / 12.9K — for stat tile values. */
export const formatCount = (n: number): string =>
  n < 10_000 ? n.toLocaleString() : compact.format(n);

/** "4.2 s", "3 m 12 s", "1 h 05 m"; null while a scan has not finished. */
export function formatDuration(start: string | null, end: string | null): string | null {
  if (!start || !end) return null;
  const seconds = Math.max(0, (Date.parse(end) - Date.parse(start)) / 1000);
  if (seconds < 60) return `${seconds < 10 ? seconds.toFixed(1) : Math.round(seconds)} s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} m ${String(Math.round(seconds % 60)).padStart(2, "0")} s`;
  return `${Math.floor(minutes / 60)} h ${String(minutes % 60).padStart(2, "0")} m`;
}

export const formatBytes = (n: number): string =>
  n < 1024 ? `${n} B` : n < 1024 ** 2 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1024 ** 2).toFixed(1)} MB`;

export const errorMessage = (err: unknown): string =>
  err instanceof Error ? err.message : String(err);
