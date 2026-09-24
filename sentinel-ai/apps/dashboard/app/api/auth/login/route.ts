import { handleAuth } from "@/lib/api/bff";
import { serverDeps } from "@/lib/api/deps";

export const dynamic = "force-dynamic";
export const POST = (req: Request) => handleAuth("login", req, serverDeps());
