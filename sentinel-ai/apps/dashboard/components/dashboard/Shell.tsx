"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import type { ReactNode } from "react";
import { Button } from "@/components/ui/primitives";
import { auth } from "@/lib/api/client";
import { cn } from "@/lib/utils/format";

/** Only sections backed by real gateway endpoints are listed; the rest (users, teams, providers, ...) arrive with their APIs. */
const NAV = [
  { href: "/dashboard", label: "Overview" },
  { href: "/events", label: "Security events" },
  { href: "/threats", label: "Threats" },
  { href: "/files", label: "File scan" },
  { href: "/policies", label: "Policies" },
  { href: "/usage", label: "Usage" },
  { href: "/api-keys", label: "API keys" },
  { href: "/users", label: "Users" },
  { href: "/teams", label: "Teams" },
  { href: "/providers", label: "Providers" },
  { href: "/settings", label: "Settings" },
];

export function Shell({ title, children }: { title: string; children: ReactNode }) {
  const path = usePathname();
  const router = useRouter();
  const logout = async () => { try { await auth.logout(); } finally { router.replace("/login"); router.refresh(); } };
  return (
    <div className="min-h-screen md:flex">
      <aside className="border-b border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900 md:min-h-screen md:w-56 md:border-b-0 md:border-r">
        <p className="mb-4 text-base font-bold tracking-tight">SentinelAI</p>
        <nav aria-label="Main" className="flex gap-1 overflow-x-auto md:flex-col">
          {NAV.map((n) => (
            <Link key={n.href} href={n.href} aria-current={path === n.href || path.startsWith(`${n.href}/`) ? "page" : undefined}
              className={cn("whitespace-nowrap rounded-md px-3 py-1.5 text-sm hover:bg-slate-100 dark:hover:bg-slate-800",
                (path === n.href || path.startsWith(`${n.href}/`)) && "bg-indigo-50 font-medium text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300")}>
              {n.label}
            </Link>
          ))}
        </nav>
        <div className="mt-4"><Button variant="secondary" onClick={logout} className="w-full">Sign out</Button></div>
      </aside>
      <main className="flex-1 p-4 md:p-6">
        <h1 className="mb-4 text-xl font-semibold">{title}</h1>
        <div className="space-y-4">{children}</div>
      </main>
    </div>
  );
}
