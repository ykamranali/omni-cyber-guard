"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle, Globe, Loader2, Plus, RadioTower, ShieldCheck, Trash2,
} from "lucide-react";
import { api, ApiError } from "@/lib/api";

/**
 * External attack surface.
 *
 * The workflow changed, deliberately. Probing a domain resolves it and opens a
 * TLS connection to a host somebody else owns, so the domain has to be
 * registered as authorized scope first — the row is the authorization. The
 * previous page took any string in a text box and dispatched a live probe at
 * it, with no permission check and no scope check anywhere in the path.
 *
 * The certificate expiry column is the reason this page earns its place: it is
 * read from the live endpoint, not from a database someone typed into.
 */

interface Domain {
  id: string;
  domain_name: string;
  ip_addresses: string[];
  registrar: string;
  registrar_note: string;
  is_active: boolean;
  cert_issuer: string;
  cert_valid_from: string | null;
  cert_valid_to: string | null;
  cert_expires_in_days: number | null;
  authorized_at: string | null;
  last_checked_at: string | null;
  probe_status: string;
  probe_message: string;
}

interface AttackSurfaceResponse {
  domains: Domain[];
  empty_state_note: string;
}

function ExpiryCell({ days }: { days: number | null }) {
  if (days === null) {
    return <span className="text-xs text-muted">Not read</span>;
  }
  if (days < 0) {
    return (
      <span className="text-xs font-medium text-red-400">
        Expired {Math.abs(days)}d ago
      </span>
    );
  }
  const tone =
    days <= 14 ? "text-red-400" : days <= 30 ? "text-amber-400" : "text-emerald-400";
  return <span className={`text-xs font-medium ${tone}`}>{days}d remaining</span>;
}

export default function AttackSurfacePage() {
  const queryClient = useQueryClient();
  const [domain, setDomain] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [formError, setFormError] = useState("");

  const { data, isLoading, error } = useQuery<AttackSurfaceResponse>({
    queryKey: ["attack-surface"],
    queryFn: () => api.get<AttackSurfaceResponse>("/attack-surface/"),
  });

  const register = useMutation({
    mutationFn: () =>
      api.post("/attack-surface/domains", {
        domain: domain.trim().toLowerCase(),
        authorization_confirmed: confirmed,
      }),
    onSuccess: () => {
      setDomain("");
      setConfirmed(false);
      setFormError("");
      void queryClient.invalidateQueries({ queryKey: ["attack-surface"] });
    },
    onError: (caught) =>
      setFormError(
        caught instanceof ApiError ? caught.message : "The domain could not be registered.",
      ),
  });

  const probe = useMutation({
    mutationFn: (id: string) => api.post(`/attack-surface/domains/${id}/probe`, {}),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["attack-surface"] }),
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/attack-surface/domains/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["attack-surface"] }),
  });

  const domains = data?.domains ?? [];

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="flex items-center gap-3 text-3xl font-bold tracking-tight text-ink">
          <Globe className="h-8 w-8 text-primary" />
          External Attack Surface
        </h1>
        <p className="mt-2 text-muted">
          DNS resolution and live TLS certificate details for the domains you
          have declared in scope.
        </p>
      </div>

      <section className="rounded-xl border border-border bg-surface p-5">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-ink">
          <ShieldCheck className="h-4 w-4 text-primary" />
          Register a domain as authorized scope
        </h2>
        <p className="mt-1 text-xs text-muted">
          Probing resolves the name and connects to it over TLS. Register only
          domains you are authorized to assess — this platform will not probe a
          host you have not declared.
        </p>

        <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-end">
          <div className="flex-1">
            <label className="mb-1 block text-xs font-medium text-muted" htmlFor="domain">
              Domain
            </label>
            <input
              id="domain"
              value={domain}
              onChange={(event) => setDomain(event.target.value)}
              placeholder="example.com"
              className="h-10 w-full rounded-lg border border-border bg-background px-3 text-sm text-ink placeholder:text-muted focus:border-primary focus:outline-none"
            />
          </div>
          <button
            type="button"
            disabled={!domain.trim() || !confirmed || register.isPending}
            onClick={() => register.mutate()}
            className="inline-flex h-10 items-center gap-2 rounded-lg bg-primary px-4 text-sm font-medium text-primary-foreground disabled:opacity-40"
          >
            {register.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Plus className="h-4 w-4" />
            )}
            Register
          </button>
        </div>

        <label className="mt-3 flex items-start gap-2 text-xs text-ink/90">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(event) => setConfirmed(event.target.checked)}
            className="mt-0.5 h-3.5 w-3.5 accent-[rgb(var(--color-primary))]"
          />
          I confirm I am authorized to assess this domain.
        </label>

        {formError && <p className="mt-2 text-xs text-red-400">{formError}</p>}
      </section>

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-400">
          <AlertTriangle className="h-5 w-5" />
          {error instanceof ApiError ? error.message : "The attack surface could not be loaded."}
        </div>
      )}

      <section className="rounded-xl border border-border bg-surface">
        <div className="border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold text-ink">Registered domains</h2>
        </div>

        {isLoading ? (
          <div className="flex h-40 items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin text-muted" />
          </div>
        ) : domains.length === 0 ? (
          <div className="p-8 text-center text-sm text-muted">
            {data?.empty_state_note || "No domains are registered."}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs uppercase tracking-wider text-muted">
                  <th className="px-5 py-3 font-medium">Domain</th>
                  <th className="px-5 py-3 font-medium">Addresses</th>
                  <th className="px-5 py-3 font-medium">Certificate issuer</th>
                  <th className="px-5 py-3 font-medium">Expiry</th>
                  <th className="px-5 py-3 font-medium">Last probed</th>
                  <th className="px-5 py-3 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {domains.map((record) => (
                  <tr
                    key={record.id}
                    className="border-b border-border/60 last:border-0 hover:bg-surface-hover"
                  >
                    <td className="px-5 py-3">
                      <div className="font-medium text-ink">{record.domain_name}</div>
                      {record.probe_message && (
                        <div className="mt-0.5 max-w-md text-[11px] text-muted">
                          {record.probe_message}
                        </div>
                      )}
                    </td>
                    <td className="px-5 py-3 text-xs text-muted">
                      {record.ip_addresses.length > 0
                        ? record.ip_addresses.join(", ")
                        : "—"}
                    </td>
                    <td className="px-5 py-3 text-xs text-muted">
                      {record.cert_issuer || "—"}
                    </td>
                    <td className="px-5 py-3">
                      <ExpiryCell days={record.cert_expires_in_days} />
                    </td>
                    <td className="px-5 py-3 text-xs text-muted">
                      {/* Never probed is a different statement from probed and
                          found nothing. */}
                      {record.last_checked_at
                        ? new Date(record.last_checked_at).toLocaleString()
                        : "Never"}
                    </td>
                    <td className="px-5 py-3">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          type="button"
                          onClick={() => probe.mutate(record.id)}
                          disabled={probe.isPending}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-border px-2.5 py-1.5 text-xs text-ink hover:bg-surface-hover disabled:opacity-40"
                        >
                          <RadioTower className="h-3.5 w-3.5" />
                          Probe
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            if (
                              window.confirm(
                                `Remove ${record.domain_name} from scope? This revokes authorization to probe it.`,
                              )
                            ) {
                              remove.mutate(record.id);
                            }
                          }}
                          className="rounded-lg border border-border p-1.5 text-muted hover:text-red-400"
                          aria-label={`Remove ${record.domain_name}`}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
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
