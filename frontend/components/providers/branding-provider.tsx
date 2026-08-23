"use client";

import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { api } from "@/lib/api";
import { useAuthStore } from "@/store/auth";
import {
  Branding,
  DEFAULT_BRANDING,
  applyBranding,
  cacheBranding,
  clearCachedBranding,
  readCachedBranding,
} from "@/lib/branding";

/**
 * Fetches the signed-in organization's branding and applies it.
 *
 * `refresh()` is exposed so the settings screen can push a change through
 * immediately after saving, rather than asking the operator to reload — which
 * is what made the feature feel broken even once the plumbing existed.
 */

interface BrandingContextValue {
  branding: Branding;
  loading: boolean;
  refresh: () => Promise<void>;
}

const BrandingContext = createContext<BrandingContextValue>({
  branding: DEFAULT_BRANDING,
  loading: true,
  refresh: async () => {},
});

export const useBranding = () => useContext(BrandingContext);

interface OrganizationResponse {
  name?: string;
  logo_url?: string | null;
  favicon_url?: string | null;
  primary_color?: string | null;
  secondary_color?: string | null;
  footer_text?: string | null;
}

function normalise(payload: OrganizationResponse): Branding {
  return {
    name: payload.name || DEFAULT_BRANDING.name,
    logo_url: payload.logo_url || null,
    favicon_url: payload.favicon_url || null,
    primary_color: payload.primary_color || DEFAULT_BRANDING.primary_color,
    secondary_color: payload.secondary_color || DEFAULT_BRANDING.secondary_color,
    footer_text: payload.footer_text || DEFAULT_BRANDING.footer_text,
  };
}

export function BrandingProvider({ children }: { children: React.ReactNode }) {
  const accessToken = useAuthStore((state) => state.accessToken);
  // Start from the cached value so the first render already matches what the
  // pre-paint script put on the document root.
  const [branding, setBranding] = useState<Branding>(
    () => readCachedBranding() ?? DEFAULT_BRANDING,
  );
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    if (!accessToken) return;
    try {
      const payload = await api.get<OrganizationResponse>("/organizations/current");
      const next = normalise(payload);
      setBranding(next);
      applyBranding(next);
      cacheBranding(next);
    } catch {
      // A branding fetch failing must never block the application. The cached
      // or default palette stays in place.
    } finally {
      setLoading(false);
    }
  }, [accessToken]);

  useEffect(() => {
    if (!accessToken) {
      // Signing out clears the cache so the next account does not briefly
      // render in the previous organization's colours.
      clearCachedBranding();
      setLoading(false);
      return;
    }
    applyBranding(branding);
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accessToken, refresh]);

  return (
    <BrandingContext.Provider value={{ branding, loading, refresh }}>
      {children}
    </BrandingContext.Provider>
  );
}
