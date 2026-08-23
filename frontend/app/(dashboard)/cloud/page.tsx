"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Cloud, Loader2 } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import {
  IntegrationPanel, IntegrationState,
} from "@/components/integrations/integration-panel";

/**
 * Cloud inventory.
 *
 * Every request now goes through `lib/api`. The previous version called
 * `fetch("/api/v1/cloud/")` — a path relative to the *frontend* origin, while
 * the API runs on a different one — so it 404'd on every deployment and the
 * page showed "Could not load cloud resources data" regardless of state.
 *
 * The counts are computed from what was actually read. When nothing has been
 * read the page says so, and says why, rather than showing a zero that reads
 * like an assessed result.
 */

interface CloudResource {
  id: string;
  provider: string;
  resource_type: string;
  resource_id: string;
  name: string;
  region: string;
  status: string;
  compliance_status: string;
  compliance_note: string;
  last_seen: string | null;
}

interface CloudResponse {
  resources: CloudResource[];
  integrations: IntegrationState[];
  empty_state_note: string;
}

export default function CloudAssetsPage() {
  const queryClient = useQueryClient();

  const { data, isLoading, error } = useQuery<CloudResponse>({
    queryKey: ["cloud"],
    queryFn: () => api.get<CloudResponse>("/cloud/"),
  });

  const runDiscovery = async (provider: string) => {
    await api.post("/cloud/scan", { provider });
    // The read happens in a worker. Rather than guessing at a delay — the old
    // page waited a blind three seconds — the socket invalidates this query
    // when the job reports back, and this refetch covers the case where the
    // job finishes before the socket delivers.
    await queryClient.invalidateQueries({ queryKey: ["cloud"] });
  };

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-muted" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-400">
          <AlertTriangle className="h-5 w-5" />
          {error instanceof ApiError ? error.message : "Cloud inventory could not be loaded."}
        </div>
      </div>
    );
  }

  const resources = data?.resources ?? [];
  const integrations = data?.integrations ?? [];
  const byProvider = resources.reduce<Record<string, number>>((totals, resource) => {
    const key = resource.provider || "Unknown";
    totals[key] = (totals[key] ?? 0) + 1;
    return totals;
  }, {});

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="flex items-center gap-3 text-3xl font-bold tracking-tight text-ink">
          <Cloud className="h-8 w-8 text-primary" />
          Cloud Inventory
        </h1>
        <p className="mt-2 text-muted">
          Read directly from your cloud provider&apos;s API. Nothing appears here
          that was not returned by a configured integration.
        </p>
      </div>

      <section>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-muted">
          Integrations
        </h2>
        <IntegrationPanel
          integrations={integrations}
          onRun={runDiscovery}
          runLabel="Read inventory"
        />
      </section>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-border bg-surface p-5">
          <p className="text-xs font-medium uppercase tracking-wider text-muted">
            Resources read
          </p>
          <p className="mt-2 text-2xl font-bold text-ink">{resources.length}</p>
        </div>
        {Object.entries(byProvider).map(([provider, count]) => (
          <div key={provider} className="rounded-xl border border-border bg-surface p-5">
            <p className="text-xs font-medium uppercase tracking-wider text-muted">
              {provider}
            </p>
            <p className="mt-2 text-2xl font-bold text-ink">{count}</p>
          </div>
        ))}
      </div>

      <section className="rounded-xl border border-border bg-surface">
        <div className="border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold text-ink">Resource inventory</h2>
        </div>

        {resources.length === 0 ? (
          <div className="p-8 text-center text-sm text-muted">
            {data?.empty_state_note || "No cloud resources have been read."}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs uppercase tracking-wider text-muted">
                  <th className="px-5 py-3 font-medium">Name</th>
                  <th className="px-5 py-3 font-medium">Provider</th>
                  <th className="px-5 py-3 font-medium">Type</th>
                  <th className="px-5 py-3 font-medium">Region</th>
                  <th className="px-5 py-3 font-medium">State</th>
                  <th className="px-5 py-3 font-medium">Posture</th>
                </tr>
              </thead>
              <tbody>
                {resources.map((resource) => (
                  <tr
                    key={resource.id}
                    className="border-b border-border/60 last:border-0 hover:bg-surface-hover"
                  >
                    <td className="px-5 py-3">
                      <div className="font-medium text-ink">{resource.name}</div>
                      <div className="text-[11px] text-muted">{resource.resource_id}</div>
                    </td>
                    <td className="px-5 py-3 text-muted">{resource.provider}</td>
                    <td className="px-5 py-3 text-muted">{resource.resource_type || "—"}</td>
                    <td className="px-5 py-3 text-muted">{resource.region || "—"}</td>
                    <td className="px-5 py-3">
                      {resource.status ? <Badge label={resource.status} /> : <span className="text-muted">—</span>}
                    </td>
                    <td className="px-5 py-3">
                      {/* UNKNOWN is the honest value: reading an inventory says
                          nothing about whether a resource is compliant. */}
                      <span
                        className="cursor-help border-b border-dotted border-muted/50 text-xs text-muted"
                        title={resource.compliance_note}
                      >
                        Not assessed
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
