import { handleAcceptInvite } from "@/lib/api/bff";
import { serverDeps } from "@/lib/api/deps";

export const dynamic = "force-dynamic";
export const POST = (req: Request) => handleAcceptInvite(req, serverDeps());
