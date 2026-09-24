import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from "react";
import { ACTION_STYLE, RISK_STYLE, cn } from "@/lib/utils/format";

export function Card({ title, action, children, className }: { title?: string; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={cn("rounded-lg border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900", className)}>
      {(title || action) && (
        <header className="mb-3 flex items-center justify-between gap-2">
          {title && <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-200">{title}</h2>}
          {action}
        </header>
      )}
      {children}
    </section>
  );
}

export function Button({ variant = "primary", className, ...p }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" }) {
  const styles = {
    primary: "bg-indigo-600 text-white hover:bg-indigo-500 disabled:bg-indigo-300",
    secondary: "border border-slate-300 bg-white text-slate-800 hover:bg-slate-50 disabled:opacity-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-slate-700",
    danger: "bg-red-600 text-white hover:bg-red-500 disabled:bg-red-300",
  }[variant];
  return <button {...p} className={cn("rounded-md px-3 py-1.5 text-sm font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 disabled:cursor-not-allowed", styles, className)} />;
}

const field = "w-full rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-900 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100";

export function Field({ label, id, error, ...p }: InputHTMLAttributes<HTMLInputElement> & { label: string; id: string; error?: string | null }) {
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-xs font-medium text-slate-600 dark:text-slate-300">{label}</label>
      <input id={id} {...p} aria-invalid={!!error} className={cn(field, error && "border-red-500")} />
      {error && <p className="mt-1 text-xs text-red-600">{error}</p>}
    </div>
  );
}

export function Select({ label, id, children, ...p }: SelectHTMLAttributes<HTMLSelectElement> & { label: string; id: string }) {
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-xs font-medium text-slate-600 dark:text-slate-300">{label}</label>
      <select id={id} {...p} className={field}>{children}</select>
    </div>
  );
}

export function RiskBadge({ level }: { level: string }) {
  return <span className={cn("inline-block rounded px-2 py-0.5 text-xs font-medium", RISK_STYLE[level] ?? RISK_STYLE.LOW)}>{level}</span>;
}
export function ActionBadge({ action }: { action: string }) {
  return <span className={cn("inline-block rounded px-2 py-0.5 text-xs font-medium", ACTION_STYLE[action] ?? ACTION_STYLE.ALLOW)}>{action}</span>;
}
export function Chip({ children }: { children: ReactNode }) {
  return <span className="inline-block rounded bg-slate-100 px-1.5 py-0.5 text-[11px] font-mono text-slate-700 dark:bg-slate-800 dark:text-slate-300">{children}</span>;
}

export function Notice({ kind = "error", children }: { kind?: "error" | "info" | "success"; children: ReactNode }) {
  const style = { error: "border-red-300 bg-red-50 text-red-800 dark:border-red-900 dark:bg-red-950 dark:text-red-200",
    info: "border-sky-300 bg-sky-50 text-sky-800 dark:border-sky-900 dark:bg-sky-950 dark:text-sky-200",
    success: "border-emerald-300 bg-emerald-50 text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950 dark:text-emerald-200" }[kind];
  return <div role={kind === "error" ? "alert" : "status"} className={cn("rounded-md border px-3 py-2 text-sm", style)}>{children}</div>;
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return <p role="status" className="text-sm text-slate-500">{label}...</p>;
}
