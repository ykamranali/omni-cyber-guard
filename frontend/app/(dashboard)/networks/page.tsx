"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle, Building2, CheckCircle2, Globe, Network as NetworkIcon, Pencil, Plus,
  ShieldCheck, Trash2,
} from "lucide-react";
import { Topbar } from "@/components/layout/topbar";
import { Button } from "@/components/ui/button";
import { Modal } from "@/components/ui/modal";
import { api, ApiError, errorMessage } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Site {
  id: string;
  name: string;
  description: string;
  location: string | null;
  network_count: number;
  asset_count: number;
}

interface NetworkRange {
  id: string;
  site_id: string | null;
  name: string;
  cidr: string;
  vlan_id: number | null;
  description: string;
  is_internet_facing: boolean;
  is_authorized_scope: boolean;
  authorization_note: string;
  asset_count: number;
}

export default function NetworksPage() {
  const queryClient = useQueryClient();
  const [siteModalOpen, setSiteModalOpen] = useState(false);
  const [networkModalOpen, setNetworkModalOpen] = useState(false);
  const [editingSite, setEditingSite] = useState<Site | null>(null);
  const [editingNetwork, setEditingNetwork] = useState<NetworkRange | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const { data: sites = [], isLoading: sitesLoading } = useQuery({
    queryKey: ["sites"],
    queryFn: () => api.get<Site[]>("/sites"),
  });

  const { data: networks = [], isLoading: networksLoading } = useQuery({
    queryKey: ["networks"],
    queryFn: () => api.get<NetworkRange[]>("/networks"),
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["sites"] });
    queryClient.invalidateQueries({ queryKey: ["networks"] });
  };

  const createSite = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post("/sites", body),
    onSuccess: () => { invalidate(); setSiteModalOpen(false); setError(null); },
    onError: (err: Error) => setError(err.message),
  });

  const createNetwork = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post("/networks", body),
    onSuccess: () => { invalidate(); setNetworkModalOpen(false); setError(null); },
    onError: (err: Error) => setError(err.message),
  });

  const toggleAuthorization = useMutation({
    mutationFn: ({ id, authorized }: { id: string; authorized: boolean }) =>
      api.patch(`/networks/${id}`, { is_authorized_scope: authorized }),
    onSuccess: invalidate,
  });

  const toggleExposure = useMutation({
    mutationFn: ({ id, exposed }: { id: string; exposed: boolean }) =>
      api.patch(`/networks/${id}`, { is_internet_facing: exposed }),
    onSuccess: invalidate,
  });

  const updateSite = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) =>
      api.patch(`/sites/${id}`, body),
    onSuccess: () => {
      invalidate();
      setSiteModalOpen(false);
      setEditingSite(null);
      setError(null);
    },
    onError: (err: Error) => setError(err.message),
  });

  const removeSite = useMutation({
    mutationFn: (id: string) => api.delete(`/sites/${id}`),
    onSuccess: () => {
      invalidate();
      setActionError(null);
    },
    onError: (err) =>
      setActionError(
        errorMessage(err, "The site could not be deleted."),
      ),
  });

  const updateNetwork = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) =>
      api.patch(`/networks/${id}`, body),
    onSuccess: () => {
      invalidate();
      setNetworkModalOpen(false);
      setEditingNetwork(null);
      setError(null);
    },
    onError: (err: Error) => setError(err.message),
  });

  const removeNetwork = useMutation({
    mutationFn: (id: string) => api.delete(`/networks/${id}`),
    onSuccess: () => {
      invalidate();
      setActionError(null);
    },
    // Deleting a range that assets sit in can be refused by the API. Without
    // this the button simply did nothing and said nothing.
    onError: (err) =>
      setActionError(
        errorMessage(err, "The network could not be deleted."),
      ),
  });

  const authorizedCount = networks.filter((n) => n.is_authorized_scope).length;

  return (
    <>
      <Topbar title="Sites & Networks" />
      <main className="flex-1 space-y-6 overflow-y-auto p-6">
        {actionError && (
          <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/5 px-4 py-3 text-sm text-red-400">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <span className="flex-1">{actionError}</span>
            <button type="button" onClick={() => setActionError(null)} className="text-xs underline">
              dismiss
            </button>
          </div>
        )}
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-ink">Sites &amp; Networks</h1>
            <p className="text-sm text-muted">
              Declare the ranges you own. A scan can only target a range recorded here as
              authorized scope.
            </p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => { setError(null); setSiteModalOpen(true); }}>
              <Building2 className="mr-2 h-4 w-4" /> Add site
            </Button>
            <Button onClick={() => { setError(null); setNetworkModalOpen(true); }}>
              <Plus className="mr-2 h-4 w-4" /> Add network
            </Button>
          </div>
        </div>

        <div className="flex gap-3 rounded-xl border border-primary/30 bg-primary/5 p-4">
          <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
          <div className="space-y-1">
            <p className="text-sm font-semibold text-ink">Authorized scope is a record of consent</p>
            <p className="text-sm leading-relaxed text-muted">
              Marking a range as authorized records who authorized it and when, in the audit log.
              Only mark ranges you own or have written permission to assess.
              {networks.length > 0 && (
                <> Currently {authorizedCount} of {networks.length} declared range
                  {networks.length === 1 ? "" : "s"} {authorizedCount === 1 ? "is" : "are"} authorized.</>
              )}
            </p>
          </div>
        </div>

        {/* Sites */}
        <section className="space-y-3">
          <h2 className="flex items-center gap-2 text-lg font-semibold text-ink">
            <Building2 className="h-5 w-5 text-primary" /> Sites
          </h2>
          {sitesLoading ? (
            <div className="rounded-xl border border-border bg-surface p-8 text-center text-muted">
              Loading sites…
            </div>
          ) : sites.length === 0 ? (
            <div className="rounded-xl border border-dashed border-border bg-surface p-8 text-center">
              <p className="text-sm text-ink/80">No sites defined</p>
              <p className="mt-1 text-xs text-muted">
                Sites group networks by location. They are optional — you can add networks without one.
              </p>
            </div>
          ) : (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {sites.map((site) => (
                <div key={site.id} className="rounded-xl border border-border bg-surface p-5">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <h3 className="truncate font-semibold text-ink">{site.name}</h3>
                      {site.location && <p className="text-xs text-muted">{site.location}</p>}
                    </div>
                    <div className="flex shrink-0 gap-1">
                      <button
                        type="button"
                        onClick={() => {
                          setEditingSite(site);
                          setError(null);
                          setSiteModalOpen(true);
                        }}
                        className="rounded-md p-1.5 text-muted hover:bg-primary/10 hover:text-primary"
                        title={`Edit ${site.name}`}
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          const warning =
                            site.network_count > 0 || site.asset_count > 0
                              ? `${site.name} has ${site.network_count} network(s) and ${site.asset_count} asset(s). They are not deleted — they lose their site.`
                              : `Delete ${site.name}?`;
                          if (confirm(warning)) removeSite.mutate(site.id);
                        }}
                        disabled={removeSite.isPending}
                        className="rounded-md p-1.5 text-muted hover:bg-critical/10 hover:text-critical disabled:opacity-40"
                        title={`Delete ${site.name}`}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </div>
                  {site.description && <p className="mt-2 text-sm text-muted">{site.description}</p>}
                  <div className="mt-4 flex gap-4 text-xs text-muted">
                    <span>{site.network_count} network{site.network_count === 1 ? "" : "s"}</span>
                    <span>{site.asset_count} asset{site.asset_count === 1 ? "" : "s"}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Networks */}
        <section className="space-y-3">
          <h2 className="flex items-center gap-2 text-lg font-semibold text-ink">
            <NetworkIcon className="h-5 w-5 text-primary" /> Networks
          </h2>

          {networksLoading ? (
            <div className="rounded-xl border border-border bg-surface p-8 text-center text-muted">
              Loading networks…
            </div>
          ) : networks.length === 0 ? (
            <div className="rounded-xl border border-dashed border-border bg-surface p-10 text-center">
              <NetworkIcon className="mx-auto h-10 w-10 text-muted/40" />
              <p className="mt-3 text-sm text-ink/80">No networks declared</p>
              <p className="mx-auto mt-1 max-w-md text-xs leading-relaxed text-muted">
                Discovery places each asset into the network that contains it, and internet
                exposure is taken from the network you declare — never inferred from an IP address.
                Add a range to start.
              </p>
            </div>
          ) : (
            <div className="overflow-hidden rounded-xl border border-border bg-surface">
              <table className="w-full text-sm">
                <thead className="border-b border-border bg-surface-hover/40 text-left text-xs uppercase tracking-wider text-muted">
                  <tr>
                    <th className="px-4 py-3 font-semibold">Network</th>
                    <th className="px-4 py-3 font-semibold">Range</th>
                    <th className="px-4 py-3 font-semibold">VLAN</th>
                    <th className="px-4 py-3 font-semibold">Assets</th>
                    <th className="px-4 py-3 font-semibold">Internet facing</th>
                    <th className="px-4 py-3 font-semibold">Authorized scope</th>
                    <th className="px-4 py-3" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {networks.map((network) => (
                    <tr key={network.id} className="hover:bg-surface-hover/40">
                      <td className="px-4 py-3">
                        <p className="font-medium text-ink">{network.name}</p>
                        {network.description && (
                          <p className="text-xs text-muted">{network.description}</p>
                        )}
                      </td>
                      <td className="px-4 py-3 font-mono text-ink/90">{network.cidr}</td>
                      <td className="px-4 py-3 text-muted">{network.vlan_id ?? "—"}</td>
                      <td className="px-4 py-3 text-muted">{network.asset_count}</td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() =>
                            toggleExposure.mutate({ id: network.id, exposed: !network.is_internet_facing })
                          }
                          className={cn(
                            "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold transition-colors",
                            network.is_internet_facing
                              ? "border-orange-500/40 bg-orange-500/10 text-orange-400"
                              : "border-border bg-surface text-muted hover:border-primary/40"
                          )}
                        >
                          <Globe className="h-3 w-3" />
                          {network.is_internet_facing ? "Exposed" : "Internal"}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() =>
                            toggleAuthorization.mutate({
                              id: network.id,
                              authorized: !network.is_authorized_scope,
                            })
                          }
                          className={cn(
                            "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold transition-colors",
                            network.is_authorized_scope
                              ? "border-green-500/40 bg-green-500/10 text-green-400"
                              : "border-critical/40 bg-critical/10 text-critical"
                          )}
                        >
                          {network.is_authorized_scope ? (
                            <><CheckCircle2 className="h-3 w-3" /> Authorized</>
                          ) : (
                            <><AlertTriangle className="h-3 w-3" /> Not authorized</>
                          )}
                        </button>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex items-center justify-end gap-1">
                          <button
                            type="button"
                            onClick={() => {
                              setEditingNetwork(network);
                              setError(null);
                              setNetworkModalOpen(true);
                            }}
                            className="rounded-md p-1.5 text-muted transition-colors hover:bg-primary/10 hover:text-primary"
                            title={`Edit ${network.name}`}
                          >
                            <Pencil className="h-4 w-4" />
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              const warning =
                                network.asset_count > 0
                                  ? `${network.name} contains ${network.asset_count} asset(s). Deleting the range does not delete them — they lose their network, and with it the declared internet-exposure that feeds their exposure score. Continue?`
                                  : `Delete ${network.name} (${network.cidr})?`;
                              if (confirm(warning)) removeNetwork.mutate(network.id);
                            }}
                            disabled={removeNetwork.isPending}
                            className="rounded-md p-1.5 text-muted transition-colors hover:bg-critical/10 hover:text-critical disabled:opacity-40"
                            title={`Delete ${network.name}`}
                          >
                            <Trash2 className="h-4 w-4" />
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
      </main>

      <Modal
        open={siteModalOpen}
        onClose={() => {
          setSiteModalOpen(false);
          setEditingSite(null);
        }}
        title={editingSite ? "Edit site" : "Add site"}
      >
        <SiteForm
          key={editingSite?.id ?? "new"}
          initial={editingSite}
          error={error}
          pending={createSite.isPending || updateSite.isPending}
          onSubmit={(body) =>
            editingSite
              ? updateSite.mutate({ id: editingSite.id, body })
              : createSite.mutate(body)
          }
        />
      </Modal>

      <Modal
        open={networkModalOpen}
        onClose={() => {
          setNetworkModalOpen(false);
          setEditingNetwork(null);
        }}
        title={editingNetwork ? "Edit network" : "Add network"}
      >
        <NetworkForm
          key={editingNetwork?.id ?? "new"}
          initial={editingNetwork}
          sites={sites}
          error={error}
          pending={createNetwork.isPending || updateNetwork.isPending}
          onSubmit={(body) =>
            editingNetwork
              ? updateNetwork.mutate({ id: editingNetwork.id, body })
              : createNetwork.mutate(body)
          }
        />
      </Modal>
    </>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="mb-1 block text-xs font-medium text-muted">{label}</label>
      {children}
      {hint && <p className="mt-1 text-[11px] leading-relaxed text-muted/80">{hint}</p>}
    </div>
  );
}

const inputClass =
  "w-full rounded-md border border-border bg-surface-hover px-3 py-2 text-sm text-ink focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary";

function SiteForm({
  initial, error, pending, onSubmit,
}: {
  /** Present when editing. Sites could be created but never corrected. */
  initial?: Site | null;
  error: string | null;
  pending: boolean;
  onSubmit: (body: Record<string, unknown>) => void;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [location, setLocation] = useState(initial?.location ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");

  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit({ name, location: location || null, description });
      }}
    >
      <Field label="Name">
        <input className={inputClass} value={name} onChange={(e) => setName(e.target.value)} required placeholder="HQ Datacenter" />
      </Field>
      <Field label="Location">
        <input className={inputClass} value={location} onChange={(e) => setLocation(e.target.value)} placeholder="Dubai, UAE" />
      </Field>
      <Field label="Description">
        <input className={inputClass} value={description} onChange={(e) => setDescription(e.target.value)} />
      </Field>
      {error && <p className="text-sm text-critical">{error}</p>}
      <Button type="submit" disabled={!name || pending} className="w-full">
        {pending ? "Saving…" : initial ? "Save changes" : "Create site"}
      </Button>
    </form>
  );
}

function NetworkForm({
  initial, sites, error, pending, onSubmit,
}: {
  /**
   * Present when editing. Only the two booleans were changeable before, so a
   * mistyped CIDR or a range that moved site was permanent.
   */
  initial?: NetworkRange | null;
  sites: Site[];
  error: string | null;
  pending: boolean;
  onSubmit: (body: Record<string, unknown>) => void;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [cidr, setCidr] = useState(initial?.cidr ?? "");
  const [siteId, setSiteId] = useState(initial?.site_id ?? "");
  const [vlan, setVlan] = useState(initial?.vlan_id ? String(initial.vlan_id) : "");
  const [internetFacing, setInternetFacing] = useState(initial?.is_internet_facing ?? false);
  const [authorized, setAuthorized] = useState(initial?.is_authorized_scope ?? false);
  const [note, setNote] = useState(initial?.authorization_note ?? "");

  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit({
          name,
          cidr,
          site_id: siteId || null,
          vlan_id: vlan ? Number(vlan) : null,
          is_internet_facing: internetFacing,
          is_authorized_scope: authorized,
          authorization_note: note,
        });
      }}
    >
      <Field label="Name">
        <input className={inputClass} value={name} onChange={(e) => setName(e.target.value)} required placeholder="Server VLAN" />
      </Field>
      <Field label="CIDR range" hint="For example 192.168.10.0/24. Scanning is restricted to private ranges.">
        <input className={inputClass} value={cidr} onChange={(e) => setCidr(e.target.value)} required placeholder="192.168.10.0/24" />
      </Field>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Site">
          <select className={inputClass} value={siteId} onChange={(e) => setSiteId(e.target.value)}>
            <option value="">No site</option>
            {sites.map((site) => (
              <option key={site.id} value={site.id}>{site.name}</option>
            ))}
          </select>
        </Field>
        <Field label="VLAN ID">
          <input className={inputClass} value={vlan} onChange={(e) => setVlan(e.target.value)} inputMode="numeric" placeholder="10" />
        </Field>
      </div>

      <label className="flex items-start gap-3 rounded-lg border border-border bg-surface-hover/40 p-3">
        <input type="checkbox" checked={internetFacing} onChange={(e) => setInternetFacing(e.target.checked)} className="mt-1" />
        <span className="text-sm">
          <span className="font-medium text-ink">Internet facing</span>
          <span className="mt-0.5 block text-xs leading-relaxed text-muted">
            Assets in this range are reachable from the internet. This raises their exposure score
            and is never inferred automatically.
          </span>
        </span>
      </label>

      <label className="flex items-start gap-3 rounded-lg border border-border bg-surface-hover/40 p-3">
        <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} className="mt-1" />
        <span className="text-sm">
          <span className="font-medium text-ink">I am authorized to assess this range</span>
          <span className="mt-0.5 block text-xs leading-relaxed text-muted">
            Recorded against your account in the audit log. Only tick this for ranges you own or
            have written permission to test.
          </span>
        </span>
      </label>

      {authorized && (
        <Field label="Authorization note" hint="Optional: reference a change request, contract or written approval.">
          <input className={inputClass} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Approved in CHG-2026-0412" />
        </Field>
      )}

      {error && <p className="text-sm text-critical">{error}</p>}
      <Button type="submit" disabled={!name || !cidr || pending} className="w-full">
        {pending ? "Saving…" : initial ? "Save changes" : "Create network"}
      </Button>
    </form>
  );
}
