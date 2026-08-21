"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity, AlertTriangle, Boxes, Cpu, Globe, Info, Network, Package,
  Server, ShieldCheck, X,
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

interface AssetSummary {
  id: string;
  hostname: string;
  ip_address: string | null;
}

interface AssetService {
  id: string;
  port: number;
  protocol: string;
  service_name: string;
  product: string;
  version: string;
  banner: string;
  is_tls: boolean;
  state: string;
  first_seen: string;
  last_seen: string;
}

interface AssetSoftware {
  id: string;
  name: string;
  vendor: string;
  version: string;
  cpe: string | null;
  detection_method: string;
  evidence: string;
}

interface AssetInterface {
  id: string;
  ip_address: string;
  mac_address: string | null;
  mac_vendor: string | null;
  is_primary: boolean;
}

interface AssetDetail {
  id: string;
  hostname: string;
  ip_address: string | null;
  mac_address: string | null;
  asset_type: string;
  status: string;
  operating_system: string | null;
  vendor: string | null;
  model: string | null;
  fingerprint_confidence: number;
  fingerprint_evidence: string[];
  criticality: string;
  data_sensitivity: string;
  is_internet_facing: boolean;
  is_production: boolean;
  site: string | null;
  department: string | null;
  first_seen: string;
  last_seen: string;
  risk_score: number;
  interfaces: AssetInterface[];
  services: AssetService[];
  software: AssetSoftware[];
  open_finding_count: number;
  critical_finding_count: number;
}

interface Finding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: string;
  finding_class: string;
  confidence: string;
  evidence: string;
  first_seen: string;
  last_seen: string;
  occurrence_count: number;
}

const CRITICALITY_OPTIONS = ["critical", "high", "medium", "low", "unassigned"];

const CLASS_STYLES: Record<string, string> = {
  vulnerability: "border-critical/40 bg-critical/10 text-critical",
  exposure: "border-orange-500/40 bg-orange-500/10 text-orange-400",
  misconfiguration: "border-yellow-500/40 bg-yellow-500/10 text-yellow-400",
  compliance: "border-purple-500/40 bg-purple-500/10 text-purple-400",
  informational: "border-border bg-surface text-muted",
};

type Tab = "overview" | "services" | "software" | "findings";

export function AssetDrawer({ asset, onClose }: { asset: AssetSummary | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<Tab>("overview");

  const { data: detail, isLoading } = useQuery({
    queryKey: ["asset-detail", asset?.id],
    queryFn: () => api.get<AssetDetail>(`/assets/${asset?.id}/detail`),
    enabled: !!asset,
  });

  const { data: findings = [] } = useQuery({
    queryKey: ["findings", asset?.id],
    queryFn: () => api.get<Finding[]>(`/findings?asset_id=${asset?.id}&open_only=true`),
    enabled: !!asset,
  });

  const setCriticality = useMutation({
    mutationFn: (criticality: string) => api.patch(`/assets/${asset?.id}`, { criticality }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["asset-detail", asset?.id] });
      queryClient.invalidateQueries({ queryKey: ["assets"] });
    },
  });

  if (!asset) return null;

  const openServices = detail?.services.filter((s) => s.state === "open") ?? [];
  const closedServices = detail?.services.filter((s) => s.state !== "open") ?? [];

  return (
    <>
      <div className="fixed inset-0 z-40 bg-background/80 backdrop-blur-sm" onClick={onClose} />
      <div className="fixed right-0 top-0 z-50 flex h-full w-full max-w-2xl flex-col border-l border-primary/20 bg-surface/95 shadow-[0_0_40px_rgba(var(--color-primary)/0.15)] backdrop-blur-xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border/50 bg-surface-hover/50 p-6">
          <div className="flex items-center gap-3">
            <div className="rounded border border-primary/50 bg-primary/10 p-2 text-primary shadow-neon">
              <Server size={20} />
            </div>
            <div>
              <h2 className="neon-text text-lg font-bold uppercase tracking-widest text-ink">
                {asset.hostname}
              </h2>
              <p className="font-mono text-xs text-muted">{asset.ip_address ?? "No IP recorded"}</p>
            </div>
          </div>
          <button onClick={onClose} className="rounded-md p-1 text-muted transition-colors hover:bg-surface-hover hover:text-ink">
            <X size={20} />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 border-b border-border/50 px-4">
          {([
            ["overview", "Overview"],
            ["services", `Services${openServices.length ? ` (${openServices.length})` : ""}`],
            ["software", `Software${detail?.software.length ? ` (${detail.software.length})` : ""}`],
            ["findings", `Findings${findings.length ? ` (${findings.length})` : ""}`],
          ] as [Tab, string][]).map(([value, label]) => (
            <button
              key={value}
              onClick={() => setTab(value)}
              className={cn(
                "border-b-2 px-3 py-3 text-sm font-medium transition-colors",
                tab === value
                  ? "border-primary text-primary"
                  : "border-transparent text-muted hover:text-ink"
              )}
            >
              {label}
            </button>
          ))}
        </div>

        <div className="flex-1 space-y-6 overflow-y-auto p-6">
          {isLoading || !detail ? (
            <p className="py-8 text-center text-sm text-muted">Loading asset record…</p>
          ) : tab === "overview" ? (
            <>
              <div className="grid grid-cols-3 gap-3">
                <Stat label="Risk score" value={(detail.risk_score || 0).toFixed(0)}
                      tone={detail.risk_score > 66 ? "critical" : detail.risk_score > 33 ? "warn" : "ok"} />
                <Stat label="Open findings" value={String(detail.open_finding_count)}
                      tone={detail.critical_finding_count > 0 ? "critical" : "neutral"} />
                <Stat label="Open services" value={String(openServices.length)} tone="neutral" />
              </div>

              {/* Classification with its evidence */}
              <Section icon={<Cpu size={14} />} title="Classification">
                <div className="rounded-xl border border-border bg-surface-hover/30 p-4">
                  <div className="flex items-center justify-between">
                    <span className="text-sm capitalize text-ink">
                      {detail.asset_type.replace(/_/g, " ")}
                    </span>
                    <span
                      className={cn(
                        "rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider",
                        detail.fingerprint_confidence >= 80
                          ? "border-green-500/40 bg-green-500/10 text-green-400"
                          : detail.fingerprint_confidence > 0
                            ? "border-yellow-500/40 bg-yellow-500/10 text-yellow-400"
                            : "border-border bg-surface text-muted"
                      )}
                    >
                      {detail.fingerprint_confidence > 0
                        ? `${detail.fingerprint_confidence}% confidence`
                        : "unclassified"}
                    </span>
                  </div>
                  {detail.fingerprint_evidence?.length > 0 && (
                    <ul className="mt-3 space-y-1 border-t border-border/50 pt-3 text-xs text-muted">
                      {detail.fingerprint_evidence.map((line, index) => (
                        <li key={index} className="flex gap-2">
                          <span className="text-primary/60">•</span>
                          <span>{line}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </Section>

              {/* Business context */}
              <Section icon={<Info size={14} />} title="Business context">
                <div className="space-y-3 rounded-xl border border-border bg-surface-hover/30 p-4">
                  <div className="flex items-center justify-between gap-4">
                    <div>
                      <p className="text-sm text-ink">Criticality</p>
                      <p className="text-[11px] leading-relaxed text-muted">
                        Set by you. Feeds the exposure score — it is never inferred.
                      </p>
                    </div>
                    <select
                      value={detail.criticality}
                      onChange={(e) => setCriticality.mutate(e.target.value)}
                      disabled={setCriticality.isPending}
                      className="rounded-md border border-border bg-surface px-2 py-1 text-sm capitalize text-ink focus:border-primary focus:outline-none"
                    >
                      {CRITICALITY_OPTIONS.map((option) => (
                        <option key={option} value={option}>{option}</option>
                      ))}
                    </select>
                  </div>
                  <Row label="Internet facing" value={detail.is_internet_facing ? "Yes" : "No"} />
                  <Row label="Production" value={detail.is_production ? "Yes" : "No"} />
                  <Row label="Data sensitivity" value={detail.data_sensitivity} />
                  <Row label="Department" value={detail.department ?? "—"} />
                </div>
              </Section>

              <Section icon={<Network size={14} />} title="Network">
                <div className="space-y-2 rounded-xl border border-border bg-surface-hover/30 p-4">
                  <Row label="Operating system" value={detail.operating_system ?? "Unknown"} />
                  <Row label="Vendor" value={detail.vendor ?? "Unknown"} />
                  <Row label="Model" value={detail.model ?? "—"} />
                  {detail.interfaces.map((iface) => (
                    <Row
                      key={iface.id}
                      label={iface.is_primary ? "Primary interface" : "Interface"}
                      value={`${iface.ip_address}${iface.mac_address ? ` · ${iface.mac_address}` : ""}${iface.mac_vendor ? ` (${iface.mac_vendor})` : ""}`}
                    />
                  ))}
                  <Row label="First seen" value={`${formatDistanceToNow(new Date(detail.first_seen))} ago`} />
                  <Row label="Last seen" value={`${formatDistanceToNow(new Date(detail.last_seen))} ago`} />
                </div>
              </Section>
            </>
          ) : tab === "services" ? (
            <Section icon={<Activity size={14} />} title="Observed services">
              {openServices.length === 0 && closedServices.length === 0 ? (
                <Empty message="No services recorded. Run a port and service scan against this asset." />
              ) : (
                <div className="space-y-2">
                  {openServices.map((service) => (
                    <ServiceRow key={service.id} service={service} />
                  ))}
                  {closedServices.length > 0 && (
                    <>
                      <p className="pt-3 text-[10px] font-bold uppercase tracking-widest text-muted">
                        No longer observed
                      </p>
                      {closedServices.map((service) => (
                        <ServiceRow key={service.id} service={service} />
                      ))}
                    </>
                  )}
                </div>
              )}
            </Section>
          ) : tab === "software" ? (
            <Section icon={<Package size={14} />} title="Identified software">
              {detail.software.length === 0 ? (
                <Empty message="No software identified. Service banners and credentialed checks populate this." />
              ) : (
                <div className="space-y-2">
                  {detail.software.map((item) => (
                    <div key={item.id} className="rounded-lg border border-border/50 bg-surface p-3">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <p className="text-sm font-semibold text-ink">
                            {item.name} {item.version && <span className="font-mono text-muted">{item.version}</span>}
                          </p>
                          <p className="mt-0.5 font-mono text-[10px] text-muted">
                            via {item.detection_method.replace(/_/g, " ")}
                          </p>
                        </div>
                        {item.cpe ? (
                          <span className="shrink-0 rounded border border-primary/30 bg-primary/10 px-1.5 py-0.5 font-mono text-[9px] text-primary">
                            CPE
                          </span>
                        ) : (
                          <span
                            title="No CPE could be derived, so this component is not automatically matched against CVE data. A guessed CPE would produce confident but wrong matches."
                            className="shrink-0 rounded border border-border px-1.5 py-0.5 text-[9px] text-muted"
                          >
                            no CPE
                          </span>
                        )}
                      </div>
                      {item.evidence && (
                        <p className="mt-2 truncate border-t border-border/40 pt-2 font-mono text-[10px] text-muted">
                          {item.evidence}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </Section>
          ) : (
            <Section icon={<AlertTriangle size={14} />} title="Open findings">
              {findings.length === 0 ? (
                <div className="rounded-xl border border-dashed border-border p-8 text-center text-muted">
                  <ShieldCheck size={24} className="mx-auto mb-2 opacity-50" />
                  <p className="text-xs">No open findings recorded for this asset.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {findings.map((finding) => (
                    <div key={finding.id} className="rounded-lg border border-border/50 bg-surface p-3">
                      <div className="flex items-start gap-3">
                        <AlertTriangle
                          size={16}
                          className={cn(
                            "mt-0.5 shrink-0",
                            finding.severity === "critical" ? "text-critical"
                              : finding.severity === "high" ? "text-orange-500"
                                : finding.severity === "medium" ? "text-yellow-500" : "text-blue-400"
                          )}
                        />
                        <div className="min-w-0 flex-1">
                          <p className="text-sm font-semibold text-ink">{finding.title}</p>
                          <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                            <span className={cn(
                              "rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider",
                              CLASS_STYLES[finding.finding_class] ?? CLASS_STYLES.informational
                            )}>
                              {finding.finding_class}
                            </span>
                            <span className="rounded border border-border px-1.5 py-0.5 text-[9px] uppercase tracking-wider text-muted">
                              {finding.confidence}
                            </span>
                            <span className="font-mono text-[10px] text-muted">
                              open {formatDistanceToNow(new Date(finding.first_seen))}
                            </span>
                            {finding.occurrence_count > 1 && (
                              <span className="font-mono text-[10px] text-muted">
                                · seen {finding.occurrence_count}×
                              </span>
                            )}
                          </div>
                          {finding.evidence && (
                            <p className="mt-2 line-clamp-2 border-t border-border/40 pt-2 font-mono text-[10px] text-muted">
                              {finding.evidence}
                            </p>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Section>
          )}
        </div>
      </div>
    </>
  );
}

function Stat({ label, value, tone }: { label: string; value: string; tone: "critical" | "warn" | "ok" | "neutral" }) {
  const toneClass = {
    critical: "text-critical",
    warn: "text-orange-500",
    ok: "text-green-500",
    neutral: "text-primary",
  }[tone];

  return (
    <div className="rounded-xl border border-border bg-surface-hover/30 p-4 text-center">
      <p className="mb-1 text-[10px] uppercase tracking-wider text-muted">{label}</p>
      <p className={cn("font-mono text-2xl font-bold drop-shadow-md", toneClass)}>{value}</p>
    </div>
  );
}

function Section({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-3">
      <h3 className="flex items-center gap-2 text-xs font-bold uppercase tracking-widest text-muted">
        {icon} {title}
      </h3>
      {children}
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-4 border-b border-border/40 pb-2 text-sm last:border-0 last:pb-0">
      <span className="shrink-0 text-muted">{label}</span>
      <span className="truncate text-right capitalize text-ink/90">{value}</span>
    </div>
  );
}

function Empty({ message }: { message: string }) {
  return (
    <div className="rounded-xl border border-dashed border-border p-8 text-center">
      <Boxes size={24} className="mx-auto mb-2 text-muted/40" />
      <p className="mx-auto max-w-xs text-xs leading-relaxed text-muted">{message}</p>
    </div>
  );
}

function ServiceRow({ service }: { service: AssetService }) {
  const closed = service.state !== "open";
  return (
    <div className={cn(
      "flex items-start justify-between gap-3 rounded-lg border border-border/50 bg-surface p-3",
      closed && "opacity-55"
    )}>
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm font-semibold text-ink">
            {service.protocol}/{service.port}
          </span>
          <span className="text-sm text-muted">{service.service_name || "unknown"}</span>
          {service.is_tls && (
            <span className="rounded border border-green-500/30 bg-green-500/10 px-1 py-0.5 text-[9px] font-bold uppercase text-green-400">
              TLS
            </span>
          )}
          {closed && (
            <span className="rounded border border-border px-1 py-0.5 text-[9px] uppercase text-muted">
              closed
            </span>
          )}
        </div>
        {(service.product || service.version) && (
          <p className="mt-1 font-mono text-[11px] text-muted">
            {service.product} {service.version}
          </p>
        )}
      </div>
      <div className="shrink-0 text-right">
        <p className="text-[10px] text-muted">
          {closed ? "last seen" : "seen"} {formatDistanceToNow(new Date(service.last_seen))} ago
        </p>
      </div>
    </div>
  );
}
