export type Role = "OWNER" | "ADMIN" | "SECURITY_ANALYST" | "DEVELOPER" | "VIEWER";
export interface User { id: string; organizationId: string; email: string; role: Role; teamIds: string[] }
