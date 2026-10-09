/**
 * Tells open streams that the API key they were authenticated with has stopped being valid.
 *
 * A request is authenticated once, when it starts; a stream can then run for minutes. Two paths end that window:
 *  - `notify(keyId)`: the revoke route on THIS gateway instance calls it right after the database update (immediate);
 *  - a poll every `pollMs`: one query per organization for the keys of all open streams, which also catches revocations made
 *    on another gateway replica, expiry, and deleted keys (bounded by the poll interval).
 * Fail-closed: if the check itself fails, the streams it covers are told "revocation_check_failed" (the stream service
 * quarantines them exactly like a revocation). Each subscription fires at most once.
 */
export type RevocationReason = "key_revoked" | "revocation_check_failed";

export interface RevocationSource {
  /** The subset of `keyIds` that is no longer usable (revoked, expired or gone) in this organization. */
  revokedAmong(organizationId: string, keyIds: string[]): Promise<string[]>;
}

interface Subscription { organizationId: string; keyId: string; onRevoked: (reason: RevocationReason) => void }

export class RevocationWatcher {
  private readonly subs = new Map<number, Subscription>();
  private seq = 0;
  private timer: NodeJS.Timeout | undefined;
  private polling = false;

  constructor(private readonly source: RevocationSource | undefined, private readonly pollMs: number) {}

  /** Watches `keyId` until the returned function is called. `onRevoked` runs at most once. */
  watch(organizationId: string, keyId: string, onRevoked: (reason: RevocationReason) => void): () => void {
    const id = ++this.seq;
    this.subs.set(id, { organizationId, keyId, onRevoked });
    if (this.source && !this.timer) {
      this.timer = setInterval(() => { void this.pollOnce(); }, this.pollMs);
      this.timer.unref();
    }
    return () => { this.subs.delete(id); if (this.subs.size === 0) this.stop(); };
  }

  /** Same-instance fast path: the key was just revoked here. */
  notify(keyId: string): void {
    for (const [id, s] of this.subs) if (s.keyId === keyId) this.fire(id, "key_revoked");
  }

  /** One poll over every open stream (exposed for tests; the timer calls it). Overlapping polls are skipped. */
  async pollOnce(): Promise<void> {
    if (!this.source || this.polling || this.subs.size === 0) return;
    this.polling = true;
    try {
      const byOrg = new Map<string, Set<string>>();
      for (const s of this.subs.values()) (byOrg.get(s.organizationId) ?? byOrg.set(s.organizationId, new Set()).get(s.organizationId)!).add(s.keyId);
      await Promise.all([...byOrg].map(async ([org, keys]) => {
        let gone: Set<string>; let reason: RevocationReason = "key_revoked";
        try { gone = new Set(await this.source!.revokedAmong(org, [...keys])); } catch { gone = keys; reason = "revocation_check_failed"; }
        for (const [id, s] of this.subs) if (s.organizationId === org && gone.has(s.keyId)) this.fire(id, reason);
      }));
    } finally { this.polling = false; }
  }

  get watching(): number { return this.subs.size; }

  stop(): void { if (this.timer) clearInterval(this.timer); this.timer = undefined; }

  private fire(id: number, reason: RevocationReason): void {
    const s = this.subs.get(id);
    if (!s) return;
    this.subs.delete(id);
    try { s.onRevoked(reason); } catch { /* a subscriber's failure must not stop the others from being told */ }
  }
}
