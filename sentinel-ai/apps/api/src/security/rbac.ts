import { ROLES, ROLE_PERMISSIONS, roleCanGrant, roleHas, type Permission, type RoleName } from "@sentinelai/shared-types";

// Roles/permissions live in @sentinelai/shared-types so the dashboard and gateway can never disagree.
export { ROLES, ROLE_PERMISSIONS, roleCanGrant };
export type { Permission, RoleName };

export interface Principal {
  organizationId: string;
  role: RoleName;
  apiKeyId: string | null;
  userId: string | null;
}

export function can(p: Principal, permission: Permission): boolean {
  return roleHas(p.role, permission);
}
