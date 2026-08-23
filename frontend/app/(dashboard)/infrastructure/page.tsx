"use client";

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle, CheckCircle2, Loader2, Lock, Plug, Plus, Search,
  Settings2, ShieldBan, ShieldCheck, Trash2, Unlock, X,
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { api, ApiError, errorMessage } from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { cn } from "@/lib/utils";

/**
 * Infrastructure protection.
 *
 * Every control on this page previously did nothing: "Block IP", "Firewall
 * Settings" and "Filter" had no handlers at all, the search box set state
 * nothing read, and the "Integrations Active" card was the literal markup
 * `<h3>2</h3>` with the vendor names "Palo Alto" and "AWS WAF" hardcoded beside
 * it. Nothing fetched integrations.
 *
 * The distinction this page has to keep clear is between a block the platform
 * has *recorded* and one a firewall has *accepted*. `recommended` means a
 * decision exists and traffic is unaffected. `enforced` means a vendor API
 * returned success. The platform never marks the second because it believes the
 * first.
 */

interface BlockedIp {
  id: string;
  ip_address: string;
  reason: string;
  status: string;
  created_at: string;
}

interface EnforcementInfo {
  platform_enforces_blocks: boolean;
  explanation: string;
  passive_monitor: Record<string, unknown>;
}

interface FirewallIntegration {
  id: string;
  name: string;
  vendor: string;
  base_url: string;
  api_identity: string;
  has_secret: boolean;
  blocklist_object: string;
  verify_tls: boolean;
  status: "not_configured" | "error" | "connected";
  status_message: string;
  last_checked_at: string | null;
  last_success_at: string | null;
  auto_block_enabled: boolean;
  auto_block_min_severity: string;
  auto_block_duration_minutes: number;
  never_block: string[];
  enforced_count: number;
  setup_guidance: string;
}

interface VendorInfo {
  vendor: string;
  setup_guidance: string;
}

const SEVERITIES = ["low", "medium", "high", "critical"] as const;

const STATUS_STYLE: Record<string, string> = {
  connected: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
  error: "border-red-500/30 bg-red-500/10 text-red-400",
  not_configured: "border-amber-500/30 bg-amber-500/10 text-amber-400",
};

function ago(value: string | null): string {
  if (!value) return "never";
  try {
    return formatDistanceToNow(new Date(value), { addSuffix: true });
  } catch {
    return "unknown";
  }
}

// --------------------------------------------------------------------------

function BlockIpModal({
  open, onClose, onSubmit, pending, error, canEnforce,
}: {
  open: boolean;
  onClose: () => void;
  onSubmit: (values: { ip: string; reason: string; enforce: boolean }) => void;
  pending: boolean;
  error: string | null;
  canEnforce: boolean;
}) {
  const [ip, setIp] = useState("");
  const [reason, setReason] = useState("");
  const [enforce, setEnforce] = useState(false);

  return (
    <Modal open={open} onClose={onClose} title="Block an address">
      <form
        className="space-y-4"
        onSubmit={(event) => {
          event.preventDefault();
          onSubmit({ ip: ip.trim(), reason: reason.trim(), enforce });
        }}
      >
        <div>
          <label className="mb-1 block text-xs font-medium text-muted">IP address</label>
          <input
            value={ip}
            onChange={(event) => setIp(event.target.value)}
            required
            placeholder="203.0.113.9"
            className="h-10 w-full rounded-lg border border-border bg-background px-3 text-sm text-ink focus:border-primary focus:outline-none"
          />
        </div>

        <div>
          <label className="mb-1 block text-xs font-medium text-muted">
            Reason
          </label>
          <input
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            required
            placeholder="Repeated authentication failures against the VPN"
            className="h-10 w-full rounded-lg border border-border bg-background px-3 text-sm text-ink focus:border-primary focus:outline-none"
          />
          <p className="mt-1 text-[11px] text-muted">
            Recorded with your account in the audit log.
          </p>
        </div>

        <label
          className={cn(
            "flex items-start gap-3 rounded-lg border p-3",
            canEnforce ? "border-border bg-surface-hover/40" : "border-border/50 opacity-60",
          )}
        >
          <input
            type="checkbox"
            checked={enforce}
            disabled={!canEnforce}
            onChange={(event) => setEnforce(event.target.checked)}
            className="mt-1"
          />
          <span className="text-sm">
            <span className="font-medium text-ink">Push to the firewall now</span>
            <span className="mt-0.5 block text-xs leading-relaxed text-muted">
              {canEnforce
                ? "Adds the address to your firewall's blocklist object through its API. The entry is only marked enforced if the firewall accepts it."
                : "No connected firewall. The block will be recorded, and traffic will be unaffected until you apply it yourself."}
            </span>
          </span>
        </label>

        {error && (
          <p className="rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-2 text-xs text-red-400">
            {error}
          </p>
        )}

        <button
          type="submit"
          disabled={!ip.trim() || !reason.trim() || pending}
          className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground disabled:opacity-50"
        >
          {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Lock className="h-4 w-4" />}
          Block address
        </button>
      </form>
    </Modal>
  );
}

// --------------------------------------------------------------------------

function FirewallModal({
  open, onClose, integration, vendors, onSaved,
}: {
  open: boolean;
  onClose: () => void;
  integration: FirewallIntegration | null;
  vendors: VendorInfo[];
  onSaved: () => void;
}) {
  const editing = Boolean(integration);
  const [form, setForm] = useState(() => ({
    name: integration?.name ?? "",
    vendor: integration?.vendor ?? vendors[0]?.vendor ?? "opnsense",
    base_url: integration?.base_url ?? "",
    api_identity: integration?.api_identity ?? "",
    api_secret: "",
    blocklist_object: integration?.blocklist_object ?? "",
    verify_tls: integration?.verify_tls ?? true,
    auto_block_enabled: integration?.auto_block_enabled ?? false,
    auto_block_min_severity: integration?.auto_block_min_severity ?? "critical",
    auto_block_duration_minutes: integration?.auto_block_duration_minutes ?? 60,
    never_block: (integration?.never_block ?? []).join(", "),
  }));
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const guidance =
    vendors.find((entry) => entry.vendor === form.vendor)?.setup_guidance ?? "";

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setPending(true);
    setError(null);

    const body: Record<string, unknown> = {
      name: form.name,
      base_url: form.base_url,
      api_identity: form.api_identity,
      blocklist_object: form.blocklist_object,
      verify_tls: form.verify_tls,
      auto_block_enabled: form.auto_block_enabled,
      auto_block_min_severity: form.auto_block_min_severity,
      auto_block_duration_minutes: Number(form.auto_block_duration_minutes),
      never_block: form.never_block
        .split(",")
        .map((entry) => entry.trim())
        .filter(Boolean),
    };
    // Omitted rather than sent empty, so editing without retyping the secret
    // leaves the stored one alone.
    if (form.api_secret) body.api_secret = form.api_secret;

    try {
      if (editing) {
        await api.patch(`/firewall/${integration!.id}`, body);
      } else {
        await api.post("/firewall", { ...body, vendor: form.vendor });
      }
      onSaved();
      onClose();
    } catch (caught) {
      setError(errorMessage(caught, "The firewall could not be saved."));
    } finally {
      setPending(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={editing ? `Firewall — ${integration!.name}` : "Connect a firewall"}
    >
      <form className="space-y-4" onSubmit={submit}>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="mb-1 block text-xs font-medium text-muted">Name</label>
            <input
              value={form.name}
              onChange={(event) => setForm({ ...form, name: event.target.value })}
              required
              placeholder="Edge firewall"
              className="h-10 w-full rounded-lg border border-border bg-background px-3 text-sm text-ink focus:border-primary focus:outline-none"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-muted">Vendor</label>
            <select
              value={form.vendor}
              disabled={editing}
              onChange={(event) => setForm({ ...form, vendor: event.target.value })}
              className="h-10 w-full rounded-lg border border-border bg-background px-3 text-sm capitalize text-ink focus:border-primary focus:outline-none disabled:opacity-60"
            >
              {vendors.map((entry) => (
                <option key={entry.vendor} value={entry.vendor}>
                  {entry.vendor}
                </option>
              ))}
            </select>
          </div>
        </div>

        {guidance && (
          <p className="rounded-lg border border-border bg-surface-hover/40 p-3 text-[11px] leading-relaxed text-muted">
            {guidance}
          </p>
        )}

        <div>
          <label className="mb-1 block text-xs font-medium text-muted">Management URL</label>
          <input
            value={form.base_url}
            onChange={(event) => setForm({ ...form, base_url: event.target.value })}
            required
            placeholder="https://firewall.internal"
            className="h-10 w-full rounded-lg border border-border bg-background px-3 text-sm text-ink focus:border-primary focus:outline-none"
          />
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="mb-1 block text-xs font-medium text-muted">
              API key / user
            </label>
            <input
              value={form.api_identity}
              onChange={(event) => setForm({ ...form, api_identity: event.target.value })}
              className="h-10 w-full rounded-lg border border-border bg-background px-3 text-sm text-ink focus:border-primary focus:outline-none"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-muted">
              API secret {editing && integration!.has_secret && "(stored)"}
            </label>
            <input
              type="password"
              value={form.api_secret}
              onChange={(event) => setForm({ ...form, api_secret: event.target.value })}
              required={!editing}
              placeholder={editing ? "Leave blank to keep" : ""}
              className="h-10 w-full rounded-lg border border-border bg-background px-3 text-sm text-ink focus:border-primary focus:outline-none"
            />
          </div>
        </div>

        <div>
          <label className="mb-1 block text-xs font-medium text-muted">
            Blocklist object
          </label>
          <input
            value={form.blocklist_object}
            onChange={(event) => setForm({ ...form, blocklist_object: event.target.value })}
            required
            placeholder="ocg_blocklist"
            className="h-10 w-full rounded-lg border border-border bg-background px-3 text-sm text-ink focus:border-primary focus:outline-none"
          />
          <p className="mt-1 text-[11px] text-muted">
            An alias or address group that already exists on the firewall and is
            referenced by your own block rule. The platform only adds and removes
            addresses — it never creates rules or changes policy.
          </p>
        </div>

        <label className="flex items-center gap-2 text-xs text-ink/90">
          <input
            type="checkbox"
            checked={form.verify_tls}
            onChange={(event) => setForm({ ...form, verify_tls: event.target.checked })}
          />
          Verify the firewall&apos;s TLS certificate
        </label>

        <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
          <label className="flex items-start gap-3">
            <input
              type="checkbox"
              checked={form.auto_block_enabled}
              onChange={(event) =>
                setForm({ ...form, auto_block_enabled: event.target.checked })
              }
              className="mt-1"
            />
            <span className="text-sm">
              <span className="font-medium text-amber-400">
                Block automatically on high-confidence events
              </span>
              <span className="mt-0.5 block text-xs leading-relaxed text-ink/90">
                The platform will cut off an address without asking. Off by
                default, and only available once a connection test has succeeded.
              </span>
            </span>
          </label>

          {form.auto_block_enabled && (
            <div className="mt-3 grid grid-cols-2 gap-3">
              <div>
                <label className="mb-1 block text-[11px] text-muted">
                  Minimum severity
                </label>
                <select
                  value={form.auto_block_min_severity}
                  onChange={(event) =>
                    setForm({ ...form, auto_block_min_severity: event.target.value })
                  }
                  className="h-9 w-full rounded-lg border border-border bg-background px-2 text-sm capitalize text-ink focus:border-primary focus:outline-none"
                >
                  {SEVERITIES.map((severity) => (
                    <option key={severity} value={severity}>
                      {severity}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-muted">
                  Expires after (minutes)
                </label>
                <input
                  type="number"
                  min={5}
                  max={10080}
                  value={form.auto_block_duration_minutes}
                  onChange={(event) =>
                    setForm({
                      ...form,
                      auto_block_duration_minutes: Number(event.target.value),
                    })
                  }
                  className="h-9 w-full rounded-lg border border-border bg-background px-2 text-sm text-ink focus:border-primary focus:outline-none"
                />
              </div>
              <div className="col-span-2">
                <label className="mb-1 block text-[11px] text-muted">
                  Never block these ranges
                </label>
                <input
                  value={form.never_block}
                  onChange={(event) => setForm({ ...form, never_block: event.target.value })}
                  placeholder="192.168.1.1/32, 10.0.0.0/8"
                  className="h-9 w-full rounded-lg border border-border bg-background px-2 text-sm text-ink focus:border-primary focus:outline-none"
                />
                <p className="mt-1 text-[11px] text-muted">
                  Comma-separated. Put your gateway, DNS resolvers and management
                  range here — an automatic block that would hit one is refused,
                  not skipped quietly.
                </p>
              </div>
            </div>
          )}
        </div>

        {error && (
          <p className="rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-2 text-xs text-red-400">
            {error}
          </p>
        )}

        <button
          type="submit"
          disabled={pending}
          className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground disabled:opacity-50"
        >
          {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plug className="h-4 w-4" />}
          {editing ? "Save changes" : "Connect firewall"}
        </button>
      </form>
    </Modal>
  );
}

// --------------------------------------------------------------------------

export default function InfrastructurePage() {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [blockModal, setBlockModal] = useState(false);
  const [blockError, setBlockError] = useState<string | null>(null);
  const [firewallModal, setFirewallModal] = useState(false);
  const [editingFirewall, setEditingFirewall] = useState<FirewallIntegration | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<string | null>(null);

  const { data: blocked = [], isLoading } = useQuery<BlockedIp[]>({
    queryKey: ["infrastructure", "blocked-ips"],
    queryFn: () => api.get<BlockedIp[]>("/infrastructure/blocked-ips"),
  });

  const { data: enforcement } = useQuery<EnforcementInfo>({
    queryKey: ["infrastructure", "enforcement"],
    queryFn: () => api.get<EnforcementInfo>("/infrastructure/enforcement"),
  });

  const { data: firewalls } = useQuery<{ integrations: FirewallIntegration[] }>({
    queryKey: ["infrastructure", "firewalls"],
    queryFn: () => api.get<{ integrations: FirewallIntegration[] }>("/firewall"),
  });

  const { data: vendorInfo } = useQuery<{ vendors: VendorInfo[]; note: string }>({
    queryKey: ["infrastructure", "firewall-vendors"],
    queryFn: () => api.get<{ vendors: VendorInfo[]; note: string }>("/firewall/vendors"),
  });

  const integrations = firewalls?.integrations ?? [];
  const connected = integrations.filter((item) => item.status === "connected");

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["infrastructure"] });
  };

  const blockIp = useMutation({
    mutationFn: (values: { ip: string; reason: string; enforce: boolean }) =>
      api.post("/infrastructure/blocked-ips", {
        ip: values.ip,
        reason: values.reason,
        enforce: values.enforce,
      }),
    onSuccess: () => {
      refresh();
      setBlockModal(false);
      setBlockError(null);
    },
    onError: (err) =>
      setBlockError(errorMessage(err, "The address could not be blocked.")),
  });

  const unblock = useMutation({
    mutationFn: (id: string) => api.delete(`/infrastructure/blocked-ips/${id}`),
    onSuccess: () => {
      refresh();
      setActionError(null);
    },
    onError: (err) =>
      setActionError(errorMessage(err, "The block could not be removed.")),
  });

  const testFirewall = useMutation({
    mutationFn: (id: string) => api.post<{ message: string }>(`/firewall/${id}/test`, {}),
    onSuccess: (result) => {
      refresh();
      setActionError(null);
      setTestResult(result.message);
    },
    onError: (err) => {
      refresh();
      setTestResult(null);
      setActionError(
        errorMessage(err, "The firewall did not answer."),
      );
    },
  });

  const removeFirewall = useMutation({
    mutationFn: (id: string) => api.delete(`/firewall/${id}`),
    onSuccess: () => {
      refresh();
      setActionError(null);
    },
    onError: (err) =>
      setActionError(
        errorMessage(err, "The integration could not be removed."),
      ),
  });

  // The search box and the status filter now actually narrow the list. Both
  // previously set state that nothing read.
  const visible = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return blocked.filter((entry) => {
      if (statusFilter && entry.status !== statusFilter) return false;
      if (!needle) return true;
      return (
        entry.ip_address.toLowerCase().includes(needle) ||
        entry.reason.toLowerCase().includes(needle)
      );
    });
  }, [blocked, search, statusFilter]);

  const enforcedCount = blocked.filter((entry) => entry.status === "enforced").length;

  return (
    <div className="space-y-6 p-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-3 text-3xl font-bold tracking-tight text-ink">
            <ShieldBan className="h-8 w-8 text-primary" />
            Infrastructure Protection
          </h1>
          <p className="mt-2 text-muted">
            Block decisions, and what your firewall has actually accepted.
          </p>
        </div>

        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => {
              setEditingFirewall(null);
              setFirewallModal(true);
            }}
            className="inline-flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm font-medium text-ink hover:bg-surface-hover"
          >
            <Settings2 className="h-4 w-4" />
            Connect firewall
          </button>
          <button
            type="button"
            onClick={() => {
              setBlockError(null);
              setBlockModal(true);
            }}
            className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground"
          >
            <Plus className="h-4 w-4" />
            Block IP
          </button>
        </div>
      </div>

      {enforcement && !enforcement.platform_enforces_blocks && connected.length === 0 && (
        <div className="flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/5 p-4">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" />
          <p className="text-sm text-ink/90">{enforcement.explanation}</p>
        </div>
      )}

      {actionError && (
        <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/5 px-4 py-3 text-sm text-red-400">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span className="flex-1">{actionError}</span>
          <button type="button" onClick={() => setActionError(null)}>
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {testResult && (
        <div className="flex items-start gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-4 py-3 text-sm text-emerald-400">
          <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
          <span className="flex-1">{testResult}</span>
          <button type="button" onClick={() => setTestResult(null)}>
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-3">
        <div className="rounded-xl border border-border bg-surface p-5">
          <p className="text-xs font-medium uppercase tracking-wider text-muted">
            Blocked addresses
          </p>
          <p className="mt-2 text-2xl font-bold text-ink">{blocked.length}</p>
        </div>
        <div className="rounded-xl border border-border bg-surface p-5">
          <p className="text-xs font-medium uppercase tracking-wider text-muted">
            Enforced at a firewall
          </p>
          <p className="mt-2 text-2xl font-bold text-ink">{enforcedCount}</p>
          <p className="mt-1 text-[11px] text-muted">
            The rest are recorded decisions; traffic is unaffected.
          </p>
        </div>
        <div className="rounded-xl border border-border bg-surface p-5">
          <p className="text-xs font-medium uppercase tracking-wider text-muted">
            Firewalls connected
          </p>
          {/* This card was the literal markup <h3>2</h3> with "Palo Alto" and
              "AWS WAF" written beside it. Nothing fetched integrations. */}
          <p className="mt-2 text-2xl font-bold text-ink">{connected.length}</p>
          <p className="mt-1 truncate text-[11px] text-muted">
            {connected.length > 0
              ? connected.map((item) => item.name).join(", ")
              : "None"}
          </p>
        </div>
      </div>

      <section className="rounded-xl border border-border bg-surface">
        <div className="border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold text-ink">Firewall integrations</h2>
        </div>

        {integrations.length === 0 ? (
          <div className="p-8 text-center text-sm text-muted">
            {vendorInfo?.note ||
              "No firewall is connected, so blocks are recorded decisions only."}
          </div>
        ) : (
          <div className="divide-y divide-border/60">
            {integrations.map((integration) => (
              <div
                key={integration.id}
                className="flex flex-wrap items-start justify-between gap-4 px-5 py-4"
              >
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="font-medium text-ink">{integration.name}</p>
                    <span className="text-[11px] uppercase tracking-wider text-muted">
                      {integration.vendor}
                    </span>
                    <span
                      className={cn(
                        "rounded-md border px-2 py-0.5 text-[10px] font-medium",
                        STATUS_STYLE[integration.status],
                      )}
                    >
                      {integration.status.replace(/_/g, " ")}
                    </span>
                    {integration.auto_block_enabled && (
                      <span className="rounded-md border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] font-medium text-amber-400">
                        auto-block ≥ {integration.auto_block_min_severity}
                      </span>
                    )}
                  </div>
                  <p className="mt-1 text-xs text-muted">
                    {integration.base_url} → {integration.blocklist_object}
                  </p>
                  {integration.status_message && (
                    <p className="mt-1 max-w-2xl text-[11px] text-muted">
                      {integration.status_message}
                    </p>
                  )}
                  <p className="mt-1 text-[11px] text-muted">
                    Last checked {ago(integration.last_checked_at)} · last success{" "}
                    {ago(integration.last_success_at)} · {integration.enforced_count}{" "}
                    address(es) pushed
                  </p>
                </div>

                <div className="flex shrink-0 items-center gap-2">
                  <button
                    type="button"
                    onClick={() => testFirewall.mutate(integration.id)}
                    disabled={testFirewall.isPending}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs text-ink hover:bg-surface-hover disabled:opacity-40"
                  >
                    {testFirewall.isPending ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <Plug className="h-3.5 w-3.5" />
                    )}
                    Test
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setEditingFirewall(integration);
                      setFirewallModal(true);
                    }}
                    className="rounded-lg border border-border p-1.5 text-muted hover:text-primary"
                    aria-label={`Edit ${integration.name}`}
                  >
                    <Settings2 className="h-3.5 w-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      if (
                        confirm(
                          `Remove ${integration.name}? Addresses already pushed stay on the firewall — this platform did not create the rule referencing them and will not silently undo it.`,
                        )
                      ) {
                        removeFirewall.mutate(integration.id);
                      }
                    }}
                    className="rounded-lg border border-border p-1.5 text-muted hover:text-red-400"
                    aria-label={`Remove ${integration.name}`}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="rounded-xl border border-border bg-surface">
        <div className="flex flex-wrap items-center gap-3 border-b border-border px-5 py-4">
          <h2 className="mr-auto text-sm font-semibold text-ink">Blocked addresses</h2>

          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Address or reason…"
              className="h-9 w-64 rounded-lg border border-border bg-background pl-9 pr-3 text-sm text-ink placeholder:text-muted focus:border-primary focus:outline-none"
            />
          </div>

          <select
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
            className="h-9 rounded-lg border border-border bg-background px-2 text-sm text-ink focus:border-primary focus:outline-none"
          >
            <option value="">Any status</option>
            <option value="recommended">Recommended</option>
            <option value="enforced">Enforced</option>
            <option value="expired">Expired</option>
          </select>
        </div>

        {isLoading ? (
          <div className="flex h-40 items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin text-muted" />
          </div>
        ) : visible.length === 0 ? (
          <div className="p-8 text-center text-sm text-muted">
            {blocked.length === 0
              ? "No addresses have been blocked."
              : "No addresses match this filter."}
          </div>
        ) : (
          <div className="divide-y divide-border/60">
            {visible.map((entry) => (
              <div
                key={entry.id}
                className="flex flex-wrap items-center justify-between gap-3 px-5 py-3"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <code className="text-sm font-medium text-ink">{entry.ip_address}</code>
                    {entry.status === "enforced" ? (
                      <span className="inline-flex items-center gap-1 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-400">
                        <ShieldCheck className="h-3 w-3" />
                        Enforced at firewall
                      </span>
                    ) : (
                      <span
                        className="cursor-help rounded-md border border-border bg-surface-hover px-2 py-0.5 text-[10px] font-medium text-muted"
                        title="A recorded decision. Traffic is unaffected until a firewall applies it."
                      >
                        {entry.status}
                      </span>
                    )}
                  </div>
                  <p className="mt-0.5 max-w-2xl text-xs text-muted">{entry.reason}</p>
                  <p className="text-[11px] text-muted">Added {ago(entry.created_at)}</p>
                </div>

                <button
                  type="button"
                  onClick={() => {
                    if (confirm(`Remove the block on ${entry.ip_address}?`)) {
                      unblock.mutate(entry.id);
                    }
                  }}
                  disabled={unblock.isPending}
                  className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs text-ink hover:bg-surface-hover disabled:opacity-40"
                >
                  <Unlock className="h-3.5 w-3.5" />
                  Unblock
                </button>
              </div>
            ))}
          </div>
        )}
      </section>

      <BlockIpModal
        open={blockModal}
        onClose={() => setBlockModal(false)}
        onSubmit={(values) => blockIp.mutate(values)}
        pending={blockIp.isPending}
        error={blockError}
        canEnforce={connected.length > 0}
      />

      <FirewallModal
        key={editingFirewall?.id ?? "new"}
        open={firewallModal}
        onClose={() => {
          setFirewallModal(false);
          setEditingFirewall(null);
        }}
        integration={editingFirewall}
        vendors={vendorInfo?.vendors ?? []}
        onSaved={refresh}
      />
    </div>
  );
}
