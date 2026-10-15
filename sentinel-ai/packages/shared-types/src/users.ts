export type Role = "OWNER" | "ADMIN" | "SECURITY_ANALYST" | "DEVELOPER" | "VIEWER" | "DEVICE_CLIENT";
export interface User { id: string; organizationId: string; email: string; role: Role; teamIds: string[] }
