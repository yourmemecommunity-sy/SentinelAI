"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button, Card, Field, Notice } from "@/components/ui/primitives";
import { auth, describeError } from "@/lib/api/client";

/** Only same-site relative paths are honoured for the post-login redirect (prevents open redirects). */
export function safeNext(next: string | null): string {
  return next && /^\/[A-Za-z0-9_\-/]*$/.test(next) && !next.startsWith("//") ? next : "/dashboard";
}

export function AuthForm({ mode, next }: { mode: "login" | "register"; next: string | null }) {
  const router = useRouter();
  const [org, setOrg] = useState(""); const [email, setEmail] = useState(""); const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null); const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      if (mode === "login") await auth.login(email, password);
      else await auth.register(org, email, password);
      router.replace(safeNext(next));
      router.refresh();
    } catch (err) {
      setError(mode === "login" ? "Invalid email or password." : describeError(err));
      if (mode === "login" && err instanceof Error && /rate_limited/.test(err.message)) setError("Too many attempts. Please wait a minute.");
    } finally { setBusy(false); setPassword(""); }
  };

  return (
    <main className="flex min-h-screen items-center justify-center p-4">
      <div className="w-full max-w-sm space-y-4">
        <div className="text-center"><p className="text-2xl font-bold tracking-tight">SentinelAI</p><p className="text-sm text-slate-500">Security gateway for enterprise AI</p></div>
        <Card title={mode === "login" ? "Sign in" : "Create your organization"}>
          <form onSubmit={submit} className="space-y-3" noValidate>
            {mode === "register" && <Field id="org" label="Organization name" value={org} onChange={(e) => setOrg(e.target.value)} required autoComplete="organization" maxLength={200} />}
            <Field id="email" label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" maxLength={254} />
            <Field id="password" label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required maxLength={128}
              autoComplete={mode === "login" ? "current-password" : "new-password"} />
            {mode === "register" && <p className="text-xs text-slate-500">At least 12 characters, not containing your email name.</p>}
            {error && <Notice>{error}</Notice>}
            <Button type="submit" disabled={busy} className="w-full">{busy ? "Please wait..." : mode === "login" ? "Sign in" : "Create account"}</Button>
          </form>
        </Card>
        <p className="text-center text-sm text-slate-500">
          {mode === "login" ? <>New here? <Link className="text-indigo-600 hover:underline" href="/register">Create an organization</Link></>
            : <>Already have an account? <Link className="text-indigo-600 hover:underline" href="/login">Sign in</Link></>}
        </p>
      </div>
    </main>
  );
}
