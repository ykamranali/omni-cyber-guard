"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuthStore } from "@/store/auth";

export default function RootPage() {
  const router = useRouter();
  const accessToken = useAuthStore((s) => s.accessToken);

  useEffect(() => {
    router.replace(accessToken ? "/dashboard" : "/login");
  }, [accessToken, router]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-background text-muted text-sm">
      Loading Omni Cyber Guard…
    </div>
  );
}
