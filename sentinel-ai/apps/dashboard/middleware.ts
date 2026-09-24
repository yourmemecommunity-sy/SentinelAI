import { NextResponse, type NextRequest } from "next/server";

const PUBLIC_PAGES = new Set(["/login", "/register", "/accept-invite"]);

/**
 * 1. Per-request CSP nonce (no 'unsafe-inline' for scripts). Next applies the nonce to its own scripts when it is
 *    present in the request's CSP header.
 * 2. Navigation gate: pages require the session marker cookie. This is UX only; authorization is enforced by the
 *    gateway on every API call.
 */
export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const loggedIn = req.cookies.get("sn_sess")?.value === "1";
  if (!pathname.startsWith("/api") && !PUBLIC_PAGES.has(pathname) && !loggedIn) {
    const url = req.nextUrl.clone();
    url.pathname = "/login";
    url.search = pathname === "/" ? "" : `?next=${encodeURIComponent(pathname)}`;
    return NextResponse.redirect(url);
  }
  if (PUBLIC_PAGES.has(pathname) && loggedIn) {
    const url = req.nextUrl.clone();
    url.pathname = "/dashboard";
    url.search = "";
    return NextResponse.redirect(url);
  }

  const nonce = btoa(crypto.randomUUID());
  const dev = process.env.NODE_ENV !== "production";
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
  const headers = new Headers(req.headers);
  headers.set("x-nonce", nonce);
  headers.set("content-security-policy", csp);
  const res = NextResponse.next({ request: { headers } });
  res.headers.set("content-security-policy", csp);
  return res;
}

// api/files is excluded on purpose: Next buffers/clones request bodies that pass through middleware (with a size cap), and file
// bytes must reach the route handler untouched. That route does its own CSRF, auth and size checks; it is not a page, so it needs no CSP nonce.
export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico|api/files/).*)"] };
