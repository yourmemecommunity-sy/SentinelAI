import type { Metadata } from "next";
import { AuthForm } from "@/components/dashboard/AuthForm";

export const metadata: Metadata = { title: "Sign in" };

export default async function LoginPage({ searchParams }: { searchParams: Promise<{ next?: string }> }) {
  return <AuthForm mode="login" next={(await searchParams).next ?? null} />;
}
