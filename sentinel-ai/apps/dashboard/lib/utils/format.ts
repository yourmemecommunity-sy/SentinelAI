export const cn = (...parts: (string | false | null | undefined)[]): string => parts.filter(Boolean).join(" ");

export function formatTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "-" : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" });
}

export function shortId(id: string): string { return id.slice(0, 8); }

export const RISK_STYLE: Record<string, string> = {
  LOW: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300",
  MEDIUM: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  HIGH: "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300",
  CRITICAL: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
};

export const ACTION_STYLE: Record<string, string> = {
  ALLOW: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
  BLOCK: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
  QUARANTINE: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
  MASK: "bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-300",
  REDACT: "bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-300",
  TOKENIZE: "bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-300",
  HASH: "bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-300",
};
