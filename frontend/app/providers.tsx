"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState, useEffect } from "react";
import { useAuthStore } from "@/store/auth";
import { api } from "@/lib/api";

function hexToRgb(hex: string) {
  const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  return result ? `${parseInt(result[1], 16)} ${parseInt(result[2], 16)} ${parseInt(result[3], 16)}` : null;
}

function BrandingProvider({ children }: { children: React.ReactNode }) {
  const user = useAuthStore((s) => s.user);
  
  useEffect(() => {
    if (!user) return;
    
    // Fetch branding on load
    api.get<any>("/organizations/current").then(org => {
      if (org.primary_color) {
        const rgb = hexToRgb(org.primary_color);
        if (rgb) document.documentElement.style.setProperty('--color-primary', rgb);
      }
      if (org.secondary_color) {
        const rgb = hexToRgb(org.secondary_color);
        if (rgb) document.documentElement.style.setProperty('--color-secondary', rgb);
      }
    }).catch(console.error);
  }, [user]);

  return <>{children}</>;
}

export function Providers({ children }: { children: React.ReactNode }) {
  const [client] = useState(() => new QueryClient({
    defaultOptions: { queries: { staleTime: 30_000, retry: 1 } },
  }));
  return (
    <QueryClientProvider client={client}>
      <BrandingProvider>
        {children}
      </BrandingProvider>
    </QueryClientProvider>
  );
}
