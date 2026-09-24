/**
 * Single source of truth for roles and permissions, used by the gateway (enforcement) and the dashboard (which options to
 * offer). The database `roles` seed must equal this table (asserted by a test in apps/api).
 */
export const ROLES = ["OWNER", "ADMIN", "SECURITY_ANALYST", "DEVELOPER", "VIEWER"] as const;
export type RoleName = (typeof ROLES)[number];

export type Permission =
  | "org:manage" | "users:manage" | "policies:write" | "policies:read" | "events:read" | "providers:manage"
  | "keys:manage" | "usage:read" | "ai:use" | "scan:use" | "audit:read" | "evaluation:run";

export const ROLE_PERMISSIONS: Readonly<Record<RoleName, readonly (Permission | "*")[]>> = {
  OWNER: ["*"],
  ADMIN: ["org:manage", "users:manage", "policies:write", "policies:read", "events:read", "providers:manage", "keys:manage",
    "usage:read", "ai:use", "scan:use", "audit:read", "evaluation:run"],
  SECURITY_ANALYST: ["policies:read", "policies:write", "events:read", "usage:read", "scan:use", "audit:read", "evaluation:run"],
  DEVELOPER: ["ai:use", "scan:use", "policies:read", "keys:manage", "usage:read"],
  VIEWER: ["policies:read", "events:read", "usage:read"],
};

/** Privilege-escalation guard: a caller may only grant a role whose permissions are a subset of their own. */
export function roleCanGrant(caller: RoleName, target: RoleName): boolean {
  const mine = ROLE_PERMISSIONS[caller];
  if (mine.includes("*")) return true;
  const wanted = ROLE_PERMISSIONS[target];
  return !wanted.includes("*") && wanted.every((p) => mine.includes(p));
}

export function roleHas(role: RoleName, permission: Permission): boolean {
  const granted = ROLE_PERMISSIONS[role];
  return granted.includes("*") || granted.includes(permission);
}
