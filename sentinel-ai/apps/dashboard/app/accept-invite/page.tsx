"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { Button, Card, Field, Notice } from "@/components/ui/primitives";
import { auth, explainError } from "@/lib/api/client";

const TOKEN_RE = /^sni_[A-Za-z0-9_-]{43}$/;

/**
 * Invitation links look like /accept-invite#sni_... . The token is in the URL FRAGMENT, which browsers never send to any
 * server and never put in Referer headers, so it does not end up in access logs. It is removed from the address bar as
 * soon as it has been read.
 */
export default function AcceptInvitePage() {
  const [token, setToken] = useState<string | null>(null);
  const [password, setPassword] = useState(""); const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  useEffect(() => {
    const t = window.location.hash.slice(1);
    setToken(TOKEN_RE.test(t) ? t : "");
    if (t) window.history.replaceState(null, "", window.location.pathname);
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== confirm) { setError("The passwords do not match."); return; }
    setBusy(true); setError(null);
    try {
      const r = await auth.acceptInvite(token!, password);
      setDone(r.role ?? "member");
    } catch (err) {
      setError(explainError(err));
    } finally { setBusy(false); setPassword(""); setConfirm(""); }
  };

  return (
    <main className="flex min-h-screen items-center justify-center p-4">
      <div className="w-full max-w-sm space-y-4">
        <div className="text-center"><p className="text-2xl font-bold tracking-tight">SentinelAI</p><p className="text-sm text-slate-500">Accept your invitation</p></div>
        <Card title="Set your password">
          {token === "" && <Notice>This invitation link is incomplete. Open the full link you were sent.</Notice>}
          {done && (
            <div className="space-y-3">
              <Notice kind="success">Your account is ready (role: {done}).</Notice>
              <Link className="text-sm font-medium text-indigo-600 underline" href="/login">Sign in</Link>
            </div>
          )}
          {token && !done && (
            <form onSubmit={submit} className="space-y-3" noValidate>
              <Field id="password" label="Password (min. 12 characters)" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={12} maxLength={128} autoComplete="new-password" />
              <Field id="confirm" label="Confirm password" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required maxLength={128} autoComplete="new-password" />
              {error && <Notice>{error}</Notice>}
              <Button type="submit" disabled={busy || password.length === 0}>{busy ? "Creating account..." : "Create account"}</Button>
            </form>
          )}
        </Card>
      </div>
    </main>
  );
}
