import type { Metadata } from "next";
import { AuthForm } from "@/components/dashboard/AuthForm";

export const metadata: Metadata = { title: "Create organization" };

export default function RegisterPage() {
  return <AuthForm mode="register" next={null} />;
}
