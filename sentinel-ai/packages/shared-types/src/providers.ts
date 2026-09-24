export type ProviderId = "gemini" | "anthropic" | "openai" | "ollama" | (string & {});
export interface ProviderConfig { id: ProviderId; organizationId: string; enabled: boolean; baseUrl?: string }
