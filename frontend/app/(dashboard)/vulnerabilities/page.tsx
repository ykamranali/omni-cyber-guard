"use client";

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldAlert, ExternalLink, Trash2 } from "lucide-react";

import { Topbar } from "@/components/layout/topbar";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { api } from "@/lib/api";

interface FindingOut {
  id: string;
  asset_id: string;
  title: string;
  description: string;
  cve_id: string | null;
  cvss_score: number | null;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "open" | "in_progress" | "remediated" | "false_positive" | "accepted_risk";
  remediation_guidance: string;
  source: string;
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const STATUS_OPTIONS = ["open", "in_progress", "remediated", "false_positive", "accepted_risk"];

export default function VulnerabilitiesPage() {
  const queryClient = useQueryClient();
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const [scanIdFilter, setScanIdFilter] = useState<string>("all");

  const { data: scans } = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.get<any[]>("/scans"),
  });

  const { data: findings, isLoading, isError } = useQuery({
    queryKey: ["findings", scanIdFilter],
    queryFn: () => {
      const params = new URLSearchParams();
      if (scanIdFilter !== "all") params.append("scan_id", scanIdFilter);
      const queryStr = params.toString();
      return api.get<FindingOut[]>(`/findings${queryStr ? `?${queryStr}` : ""}`);
    },
  });

  const updateStatus = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      api.patch<FindingOut>(`/findings/${id}`, { status }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["findings"] }),
  });

  const [selectedFindingIds, setSelectedFindingIds] = useState<Set<string>>(new Set());

  const deleteBulkFindings = useMutation({
    mutationFn: (ids: string[]) => api.delete("/findings/bulk", ids),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      setSelectedFindingIds(new Set());
      setExpandedId(null);
    },
  });

  const deleteFinding = useMutation({
    mutationFn: (id: string) => api.delete(`/findings/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["findings"] });
    },
  });

  const toggleFindingSelection = (id: string) => {
    const newSet = new Set(selectedFindingIds);
    if (newSet.has(id)) newSet.delete(id);
    else newSet.add(id);
    setSelectedFindingIds(newSet);
  };

  const toggleAllFindings = () => {
    if (!findings) return;
    if (selectedFindingIds.size === findings.length) {
      setSelectedFindingIds(new Set());
    } else {
      setSelectedFindingIds(new Set(findings.map(f => f.id)));
    }
  };

  const filtered = useMemo(() => {
    if (!findings) return [];
    return findings
      .filter((f) => severityFilter === "all" || f.severity === severityFilter)
      .filter((f) => statusFilter === "all" || f.status === statusFilter)
      .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  }, [findings, severityFilter, statusFilter]);

  return (
    <>
      <Topbar title="Vulnerabilities" />
      <main className="flex-1 space-y-4 overflow-y-auto p-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-3">
            <FilterSelect label="Severity" value={severityFilter} onChange={setSeverityFilter}
              options={["all", "critical", "high", "medium", "low", "info"]} />
            <FilterSelect label="Status" value={statusFilter} onChange={setStatusFilter}
              options={["all", ...STATUS_OPTIONS]} />
            <label className="flex items-center gap-2 text-xs text-muted">
              Scan
              <select
                value={scanIdFilter}
                onChange={(e) => setScanIdFilter(e.target.value)}
                className="h-8 rounded-md border border-border bg-surface px-2 text-xs text-ink focus:outline-none focus:ring-2 focus:ring-primary/40"
              >
                <option value="all">All Scans</option>
                {scans?.filter(s => s.status === "completed").map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.target_cidr} ({new Date(s.created_at).toLocaleDateString()})
                  </option>
                ))}
              </select>
            </label>
            <span className="text-xs text-muted">{filtered.length} finding(s)</span>
          </div>
        </div>

        <Card className="overflow-hidden p-0">
          <div className="flex items-center justify-between border-b border-border px-5 py-3 bg-surface-hover/50">
            <div className="flex items-center gap-3">
              {findings && findings.length > 0 && (
                <input
                  type="checkbox"
                  className="h-4 w-4 rounded border-border text-primary focus:ring-primary/40"
                  checked={selectedFindingIds.size === findings.length}
                  onChange={toggleAllFindings}
                />
              )}
              <span className="text-xs font-medium text-muted uppercase tracking-wide">Vulnerabilities</span>
            </div>
            {selectedFindingIds.size > 0 && (
              <button
                className="rounded border border-critical/50 bg-critical/10 px-2 py-1 text-xs uppercase tracking-wider text-critical hover:bg-critical/20"
                onClick={() => {
                  if (confirm(`Are you sure you want to delete ${selectedFindingIds.size} vulnerability(ies)?`)) {
                    deleteBulkFindings.mutate(Array.from(selectedFindingIds));
                  }
                }}
                disabled={deleteBulkFindings.isPending}
              >
                {deleteBulkFindings.isPending ? "Deleting..." : `Delete Selected (${selectedFindingIds.size})`}
              </button>
            )}
          </div>

          {isLoading && <p className="p-6 text-sm text-muted">Loading findings…</p>}
          {isError && <p className="p-6 text-sm text-critical">Unable to load findings from the API.</p>}
          {findings && findings.length === 0 && (
            <p className="p-6 text-sm text-muted">
              No findings yet. Findings appear here from manual entry, or automatically after a network scan detects a risky exposed service.
            </p>
          )}

          {filtered.length > 0 && (
            <div className="divide-y divide-border/60">
              {filtered.map((f) => (
                <div key={f.id} className="p-4">
                  <div className="flex items-start gap-4">
                    <input
                      type="checkbox"
                      className="mt-1 h-4 w-4 rounded border-border text-primary focus:ring-primary/40"
                      checked={selectedFindingIds.has(f.id)}
                      onChange={() => toggleFindingSelection(f.id)}
                    />
                    <div className="flex-1">
                      <div
                        className="flex cursor-pointer items-start justify-between gap-4"
                        onClick={() => setExpandedId(expandedId === f.id ? null : f.id)}
                      >
                        <div className="flex min-w-0 items-start gap-3">
                          <ShieldAlert size={16} className="mt-0.5 shrink-0 text-high" />
                          <div className="min-w-0">
                            <p className="truncate text-sm font-medium text-ink">{f.title}</p>
                            <p className="mt-0.5 text-xs text-muted">
                              {f.cve_id ? `${f.cve_id} · ` : ""}
                              {f.cvss_score != null ? `CVSS ${f.cvss_score} · ` : ""}
                              Source: {f.source === "network_scan" ? "Network scan" : "Manual entry"}
                            </p>
                          </div>
                        </div>
                        <div className="flex shrink-0 items-center gap-2">
                          <Badge label={f.severity} />
                          <Badge label={f.status} />
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              if (confirm("Are you sure you want to delete this vulnerability?")) {
                                deleteFinding.mutate(f.id);
                              }
                            }}
                            disabled={deleteFinding.isPending}
                            className="ml-2 rounded-md p-1 text-muted hover:bg-critical/10 hover:text-critical"
                            title="Delete Vulnerability"
                          >
                            <Trash2 size={15} />
                          </button>
                        </div>
                      </div>

                  {expandedId === f.id && (
                    <div className="ml-7 mt-3 space-y-3 rounded-lg bg-surface-hover/40 p-3 text-sm">
                      <p className="text-ink/80">{f.description}</p>
                      <div>
                        <p className="mb-1 text-xs font-medium uppercase tracking-wide text-muted">
                          Remediation guidance
                        </p>
                        <p className="text-ink/75">{f.remediation_guidance || "No remediation guidance recorded."}</p>
                      </div>
                      {f.cve_id && (
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`}
                          target="_blank"
                          rel="noreferrer"
                          className="flex w-fit items-center gap-1 text-xs text-primary hover:underline"
                        >
                          View {f.cve_id} on NVD <ExternalLink size={11} />
                        </a>
                      )}
                      <div className="flex items-center gap-2 pt-1">
                        <span className="text-xs text-muted">Update status:</span>
                        <select
                          value={f.status}
                          onChange={(e) => updateStatus.mutate({ id: f.id, status: e.target.value })}
                          className="h-8 rounded-md border border-border bg-surface px-2 text-xs text-ink focus:outline-none focus:ring-2 focus:ring-primary/40"
                        >
                          {STATUS_OPTIONS.map((s) => (
                            <option key={s} value={s}>{s.replace(/_/g, " ")}</option>
                          ))}
                        </select>
                      </div>
                    </div>
                  )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      </main>
    </>
  );
}

function FilterSelect({
  label, value, onChange, options,
}: { label: string; value: string; onChange: (v: string) => void; options: string[] }) {
  return (
    <label className="flex items-center gap-2 text-xs text-muted">
      {label}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="h-8 rounded-md border border-border bg-surface px-2 text-xs text-ink capitalize focus:outline-none focus:ring-2 focus:ring-primary/40"
      >
        {options.map((o) => (
          <option key={o} value={o} className="capitalize">{o.replace(/_/g, " ")}</option>
        ))}
      </select>
    </label>
  );
}
