"use client";

import { FormEvent, useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Building2 } from "lucide-react";

import { Topbar } from "@/components/layout/topbar";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { OrgFormModal, OrgFormValues } from "@/components/organizations/org-form-modal";
import { api, ApiError } from "@/lib/api";
import { useAuthStore } from "@/store/auth";

interface OrganizationOut {
  id: string;
  name: string;
  slug: string;
  is_active: boolean;
  logo_url: string | null;
  primary_color: string;
  secondary_color: string;
  footer_text: string;
  subscription_plan: string;
  license_seats: number;
}

export default function OrganizationsPage() {
  const queryClient = useQueryClient();
  const user = useAuthStore((s) => s.user);
  const [modalOpen, setModalOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [brandingSaved, setBrandingSaved] = useState(false);

  const { data: currentOrg } = useQuery({
    queryKey: ["org-current"],
    queryFn: () => api.get<OrganizationOut>("/organizations/current"),
  });

  const { data: allOrgs } = useQuery({
    queryKey: ["orgs-all"],
    queryFn: () => api.get<OrganizationOut[]>("/organizations"),
    enabled: !!user?.is_super_admin,
    retry: false,
  });

  const [branding, setBranding] = useState({ primary_color: "", secondary_color: "", footer_text: "" });
  useEffect(() => {
    if (currentOrg) {
      setBranding({
        primary_color: currentOrg.primary_color,
        secondary_color: currentOrg.secondary_color,
        footer_text: currentOrg.footer_text,
      });
    }
  }, [currentOrg]);

  const updateBranding = useMutation({
    mutationFn: () => api.patch<OrganizationOut>("/organizations/current/branding", branding),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["org-current"] });
      setBrandingSaved(true);
      setTimeout(() => setBrandingSaved(false), 2500);
    },
  });

  const createOrg = useMutation({
    mutationFn: (values: OrgFormValues) => api.post<OrganizationOut>("/organizations", values),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["orgs-all"] });
      setModalOpen(false);
      setError(null);
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : "Failed to create organization"),
  });

  function handleBrandingSubmit(e: FormEvent) {
    e.preventDefault();
    updateBranding.mutate();
  }

  return (
    <>
      <Topbar title="Organizations" />
      <main className="flex-1 space-y-6 overflow-y-auto p-6">
        <Card>
          <CardHeader><CardTitle>Your Organization Branding</CardTitle></CardHeader>
          {currentOrg ? (
            <form onSubmit={handleBrandingSubmit} className="max-w-lg space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="mb-1 block text-xs text-muted">Primary color</label>
                  <div className="flex items-center gap-2">
                    <input type="color" value={branding.primary_color} onChange={(e) => setBranding((b) => ({ ...b, primary_color: e.target.value }))} className="h-10 w-10 rounded border border-border bg-transparent" />
                    <Input value={branding.primary_color} onChange={(e) => setBranding((b) => ({ ...b, primary_color: e.target.value }))} />
                  </div>
                </div>
                <div>
                  <label className="mb-1 block text-xs text-muted">Secondary color</label>
                  <div className="flex items-center gap-2">
                    <input type="color" value={branding.secondary_color} onChange={(e) => setBranding((b) => ({ ...b, secondary_color: e.target.value }))} className="h-10 w-10 rounded border border-border bg-transparent" />
                    <Input value={branding.secondary_color} onChange={(e) => setBranding((b) => ({ ...b, secondary_color: e.target.value }))} />
                  </div>
                </div>
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted">Footer text</label>
                <Input value={branding.footer_text} onChange={(e) => setBranding((b) => ({ ...b, footer_text: e.target.value }))} />
              </div>
              <div className="flex items-center gap-3 pt-1">
                <Button type="submit" disabled={updateBranding.isPending}>
                  {updateBranding.isPending ? "Saving…" : "Save Branding"}
                </Button>
                {brandingSaved && <span className="text-xs text-low">Saved.</span>}
              </div>
              <p className="text-xs text-muted">
                Plan: <span className="capitalize text-ink/70">{currentOrg.subscription_plan}</span> · {currentOrg.license_seats} licensed seats
              </p>
            </form>
          ) : (
            <p className="text-sm text-muted">Loading…</p>
          )}
        </Card>

        {user?.is_super_admin && (
          <Card>
            <CardHeader>
              <CardTitle>All Organizations (Platform Admin)</CardTitle>
              <Button size="sm" onClick={() => setModalOpen(true)}>
                <Plus size={14} /> New Organization
              </Button>
            </CardHeader>

            {error && <p className="mb-3 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">{error}</p>}

            {allOrgs && allOrgs.length > 0 ? (
              <div className="divide-y divide-border/60">
                {allOrgs.map((org) => (
                  <div key={org.id} className="flex items-center justify-between py-3">
                    <div className="flex items-center gap-3">
                      <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-surface-hover">
                        <Building2 size={16} className="text-primary" />
                      </div>
                      <div>
                        <p className="text-sm font-medium text-ink">{org.name}</p>
                        <p className="text-xs text-muted">{org.slug} · {org.license_seats} seats · {org.subscription_plan}</p>
                      </div>
                    </div>
                    <span className={`text-xs ${org.is_active ? "text-low" : "text-muted"}`}>
                      {org.is_active ? "Active" : "Inactive"}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted">No other organizations yet.</p>
            )}
          </Card>
        )}
      </main>

      <OrgFormModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        submitting={createOrg.isPending}
        onSubmit={(values) => createOrg.mutate(values)}
      />
    </>
  );
}
