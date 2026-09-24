import { handleProxy } from "@/lib/api/bff";
import { serverDeps } from "@/lib/api/deps";

export const dynamic = "force-dynamic";
type Ctx = { params: Promise<{ path: string[] }> };
const handler = async (req: Request, ctx: Ctx) => handleProxy(req, (await ctx.params).path, serverDeps());
export const GET = handler;
export const POST = handler;
export const PUT = handler;
export const DELETE = handler;
export const PATCH = handler;
