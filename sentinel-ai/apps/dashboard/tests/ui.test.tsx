// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { StackedBars, byDay } from "@/components/charts/StackedBars";
import { safeNext } from "@/components/dashboard/AuthForm";
import { PolicyEditor } from "@/components/policies/PolicyEditor";
import { EventsTable } from "@/components/security-events/EventsTable";
import { computeStats, entityBreakdown, isThreat } from "@/lib/utils/stats";
import { allowedActions, isAllowForbidden, validatePolicy } from "@/lib/validation/policy";
import type { SecurityEvent, UsageRow } from "@/types/api";

afterEach(cleanup);

const ev = (over: Partial<SecurityEvent> = {}): SecurityEvent => ({
  id: "11111111-1111-4111-8111-111111111111", request_id: "r", user_id: null, api_key_id: null, application: null, provider: "gemini", model: null,
  direction: "INPUT", event_type: "ai_request", risk_level: "LOW", risk_score: 5, action: "ALLOW", entity_types: [], policy_id: "p@1",
  failed_closed: false, fail_closed_reason: null, detector_version: "v", latency_ms: 1, timestamp: "2026-09-19T10:00:00.000Z", ...over,
});

describe("policy validation (mirrors the gateway)", () => {
  it("forbids ALLOW for credentials, cards, threats and CRITICAL severity", () => {
    for (const e of ["API_KEY", "PRIVATE_KEY", "CREDIT_CARD", "PASSWORD", "PROMPT_INJECTION"] as const) expect(isAllowForbidden(e, undefined)).toBe(true);
    expect(isAllowForbidden("EMAIL", "CRITICAL")).toBe(true);
    expect(isAllowForbidden("EMAIL", undefined)).toBe(false);
    expect(allowedActions("API_KEY", undefined)).not.toContain("ALLOW");
    expect(allowedActions("EMAIL", undefined)).toContain("ALLOW");
  });

  it("reports precise problems without echoing values", () => {
    expect(validatePolicy("ok-id", [{ entity: "API_KEY", action: "ALLOW" }])[0]).toMatch(/Rule 1: API_KEY cannot be ALLOWed/);
    expect(validatePolicy("", [])[0]).toMatch(/Policy id/);
    expect(validatePolicy("../x", [])[0]).toMatch(/Policy id/);
    expect(validatePolicy("ok", [{ entity: "EMAIL", action: "MASK", min_confidence: 2 }])[0]).toMatch(/confidence/);
    expect(validatePolicy("ok", [{ entity: "EMAIL", action: "MASK" }])).toEqual([]);
    expect(validatePolicy("ignored", [], { requireId: false })).toEqual([]);
  });
});

describe("PolicyEditor", () => {
  const setup = (initial = [{ entity: "EMAIL", action: "MASK" }] as never) => {
    const onSubmit = vi.fn(async () => {});
    render(<PolicyEditor policyId={null} initialRules={initial} onSubmit={onSubmit} onCancel={() => {}} />);
    return onSubmit;
  };

  it("does not offer ALLOW for a credential entity, and moves an existing ALLOW off it when the entity changes", () => {
    setup([{ entity: "EMAIL", action: "ALLOW" }] as never);
    const action = screen.getByLabelText("Action") as HTMLSelectElement;
    expect(action.value).toBe("ALLOW");
    fireEvent.change(screen.getByLabelText("Entity"), { target: { value: "API_KEY" } });
    expect((screen.getByLabelText("Action") as HTMLSelectElement).value).toBe("BLOCK");
    const allowOption = [...(screen.getByLabelText("Action") as HTMLSelectElement).options].find((o) => o.value === "ALLOW")!;
    expect(allowOption.disabled).toBe(true);
    expect(allowOption.textContent).toMatch(/not permitted/);
  });

  it("raising the severity floor to CRITICAL also forbids ALLOW", () => {
    setup([{ entity: "EMAIL", action: "ALLOW" }] as never);
    fireEvent.change(screen.getByLabelText("Severity floor"), { target: { value: "CRITICAL" } });
    expect((screen.getByLabelText("Action") as HTMLSelectElement).value).toBe("BLOCK");
  });

  it("blocks submission with an invalid policy id and does not call the API", async () => {
    const onSubmit = setup();
    fireEvent.change(screen.getByLabelText("Policy id"), { target: { value: "bad id!" } });
    fireEvent.click(screen.getByRole("button", { name: "Create policy" }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/Policy id/);
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("submits a valid policy and surfaces server errors", async () => {
    const onSubmit = vi.fn(async () => { throw new Error("payments: rule rejected"); });
    render(<PolicyEditor policyId={null} initialRules={[{ entity: "EMAIL", action: "REDACT" }]} onSubmit={onSubmit} onCancel={() => {}} />);
    fireEvent.change(screen.getByLabelText("Policy id"), { target: { value: "eng-policy" } });
    fireEvent.click(screen.getByRole("button", { name: "Create policy" }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledWith("eng-policy", [{ entity: "EMAIL", action: "REDACT" }]));
    expect((await screen.findByRole("alert")).textContent).toContain("payments: rule rejected");
  });

  it("editing an existing policy locks its id and offers a new version", () => {
    render(<PolicyEditor policyId="eng" initialRules={[]} onSubmit={async () => {}} onCancel={() => {}} />);
    expect((screen.getByLabelText("Policy id") as HTMLInputElement).disabled).toBe(true);
    expect(screen.getByRole("button", { name: "Save as new version" })).toBeTruthy();
  });

  it("rules can be added and removed", () => {
    setup();
    fireEvent.click(screen.getByRole("button", { name: "Add rule" }));
    expect(screen.getAllByLabelText("Entity")).toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name: "Remove rule 1" }));
    expect(screen.getAllByLabelText("Entity")).toHaveLength(1);
  });
});

describe("EventsTable", () => {
  it("renders metadata (entity types, action, risk) and shows an empty state", () => {
    render(<EventsTable events={[ev({ action: "MASK", risk_level: "MEDIUM", entity_types: ["EMAIL", "PHONE"], failed_closed: true })]} />);
    expect(screen.getByText("MASK")).toBeTruthy();
    expect(screen.getByText("EMAIL")).toBeTruthy();
    expect(screen.getByText("fail-closed")).toBeTruthy();
    expect(screen.getByRole("link", { name: "11111111" }).getAttribute("href")).toBe("/events/11111111-1111-4111-8111-111111111111");
    cleanup();
    render(<EventsTable events={[]} />);
    expect(screen.getByText(/No events match/)).toBeTruthy();
  });

  it("escapes hostile strings instead of interpreting them as HTML", () => {
    const { container } = render(<EventsTable events={[ev({ provider: "<img src=x onerror=alert(1)>", policy_id: "<script>alert(1)</script>" })]} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(container.textContent).toContain("<script>alert(1)</script>");
  });
});

describe("stats", () => {
  const events = [
    ev({ action: "BLOCK", risk_level: "CRITICAL", entity_types: ["AWS_CREDENTIAL"] }),
    ev({ action: "MASK", entity_types: ["EMAIL"] }),
    ev({ action: "BLOCK", risk_level: "HIGH", entity_types: ["PROMPT_INJECTION"] }),
    ev({ direction: "OUTPUT", event_type: "ai_response", action: "BLOCK", risk_level: "CRITICAL", entity_types: ["PRIVATE_KEY"] }),
    ev({ action: "BLOCK", risk_level: "CRITICAL", failed_closed: true }),
    ev(),
  ];
  const usage: UsageRow[] = [{ day: "2026-09-18", provider: "gemini", requests: 10, blocked: 2, sanitized: 3 }, { day: "2026-09-19", provider: "gemini", requests: 5, blocked: 0, sanitized: 1 }, { day: "2026-09-19", provider: "echo", requests: 4, blocked: 1, sanitized: 0 }];

  it("counts requests from INPUT events only, and threat categories from all events", () => {
    const s = computeStats(events, usage);
    expect(s).toMatchObject({ totalRequests: 5, blocked: 3, masked: 1, critical: 3, high: 1, pii: 1, secrets: 2, promptInjection: 1, failedClosed: 1 });
    expect(s.providers).toEqual([{ provider: "gemini", requests: 15 }, { provider: "echo", requests: 4 }]);
  });

  it("isThreat and entityBreakdown", () => {
    expect(events.filter(isThreat)).toHaveLength(4);
    expect(entityBreakdown(events)[0]!.count).toBe(1);
    expect(computeStats([], [])).toMatchObject({ totalRequests: 0, providers: [] });
  });

  it("chart aggregation: per-day totals never go negative and render an accessible fallback table", () => {
    expect(byDay(usage)).toEqual([{ day: "2026-09-18", allowed: 5, sanitized: 3, blocked: 2 }, { day: "2026-09-19", allowed: 7, sanitized: 1, blocked: 1 }]);
    expect(byDay([{ day: "d", provider: "p", requests: 1, blocked: 2, sanitized: 2 }])[0]!.allowed).toBe(0);
    render(<StackedBars rows={usage} />);
    expect(screen.getByRole("img").getAttribute("aria-label")).toMatch(/2 days/);
    expect(screen.getByRole("table", { hidden: true })).toBeTruthy();
    cleanup();
    render(<StackedBars rows={[]} />);
    expect(screen.getByText(/No usage recorded/)).toBeTruthy();
  });
});

describe("post-login redirect (open-redirect protection)", () => {
  it("only honours same-site relative paths", () => {
    expect(safeNext("/events")).toBe("/events");
    expect(safeNext("/events/abc-123")).toBe("/events/abc-123");
    for (const bad of [null, "", "//evil.test", "https://evil.test", "javascript:alert(1)", "/\\evil.test", "/a?b=c", "evil", "/../x%2f"]) expect(safeNext(bad), String(bad)).toBe("/dashboard");
  });
});

describe("role/permission table shared with the gateway (what the API-keys page offers)", () => {
  it("a DEVELOPER may grant only DEVELOPER; ADMIN everything but OWNER; VIEWER cannot manage keys", async () => {
    const { ROLES, roleCanGrant, roleHas } = await import("@sentinelai/shared-types");
    expect(ROLES.filter((r) => roleCanGrant("DEVELOPER", r))).toEqual(["DEVELOPER"]);
    expect(ROLES.filter((r) => roleCanGrant("ADMIN", r))).toEqual(["ADMIN", "SECURITY_ANALYST", "DEVELOPER", "VIEWER"]);
    expect(ROLES.filter((r) => roleCanGrant("OWNER", r))).toEqual([...ROLES]);
    expect(roleHas("VIEWER", "keys:manage")).toBe(false);
    expect(roleHas("SECURITY_ANALYST", "keys:manage")).toBe(false);
    expect(roleHas("DEVELOPER", "keys:manage") && roleHas("ADMIN", "keys:manage") && roleHas("OWNER", "keys:manage")).toBe(true);
  });
});
