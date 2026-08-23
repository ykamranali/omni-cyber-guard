"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";

/**
 * Application-wide providers.
 *
 * This file used to declare a second, local BrandingProvider that fetched
 * /organizations/current and wrote --color-primary and --color-secondary
 * straight onto the document root. The canonical one lives in
 * components/providers/branding-provider.tsx and is mounted by the dashboard
 * layout, so both were running: two fetches of the same endpoint, and two
 * writers of the same CSS variables with no defined ordering between them.
 * Whichever resolved last won, which is a poor way to decide what colour an
 * operator's platform is.
 *
 * The duplicate is gone. Branding is applied in exactly one place, plus the
 * pre-paint script in app/layout.tsx that restores the cached palette before
 * first paint so a branded deployment does not flash the default colours.
 */
export function Providers({ children }: { children: React.ReactNode }) {
  const [client] = useState(
    () =>
      new QueryClient({
        defaultOptions: { queries: { staleTime: 30_000, retry: 1 } },
      }),
  );

  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}
