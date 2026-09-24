import type { Metadata } from "next";
import type { ReactNode } from "react";
import "@/styles/globals.css";

// Every page is rendered per request: the CSP nonce (middleware.ts) can only be applied to dynamically rendered HTML.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: { default: "SentinelAI", template: "%s | SentinelAI" },
  description: "Security gateway for enterprise AI",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
