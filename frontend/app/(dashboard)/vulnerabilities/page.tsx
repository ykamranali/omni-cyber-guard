"use client";

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldAlert, ExternalLink, Trash2, Folder, ChevronDown, ChevronRight } from "lucide-react";

import { Topbar } from "@/components/layout/topbar";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Modal } from "@/components/ui/modal";
import { formatDistanceToNow } from "date-fns";

interface FindingOut {
  id: string;
  asset_id: string;
  title: string;
  description: string;
  evidence: string;
  finding_class: "vulnerability" | "exposure" | "misconfiguration" | "compliance" | "informational";
  confidence: "confirmed" | "probable" | "possible";
  cve_id: string | null;
  cvss_score: number | null;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: string;
  remediation_guidance: string;
  source: string;
  scan_job_id: string | null;
  first_seen: string;
  last_seen: string;
  occurrence_count: number;
  resolved_at: string | null;
}

interface FindingsSummary {
  open_by_severity: Record<string, number>;
  open_by_class: Record<string, number>;
  open_by_confidence: Record<string, number>;
  total_open: number;
  total_resolved: number;
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const STATUS_OPTIONS = [
  "open", "acknowledged", "in_progress", "mitigated", "remediated",
  "false_positive", "accepted_risk",
];
const CLASS_OPTIONS = ["vulnerability", "exposure", "misconfiguration", "compliance", "informational"];

/**
 * Class and confidence are shown on every row because they change what the
 * row means. "Port 3389 is open" and "this host matches CVE-2019-0708" are
 * different assertions backed by different evidence, and a single undifferentiated
 * finding count hides that difference entirely.
 */
const CLASS_STYLES: Record<string, string> = {
  vulnerability: "border-critical/40 bg-critical/10 text-critical",
  exposure: "border-orange-500/40 bg-orange-500/10 text-orange-400",
  misconfiguration: "border-yellow-500/40 bg-yellow-500/10 text-yellow-400",
  compliance: "border-purple-500/40 bg-purple-500/10 text-purple-400",
  informational: "border-border bg-surface text-muted",
};

const CONFIDENCE_HINTS: Record<string, string> = {
  confirmed: "The defect itself was observed directly.",
  probable: "Strong evidence, but inferred — a version banner can be wrong in both directions.",
  possible: "Weak or indirect evidence. Verify before acting.",
};

export default function VulnerabilitiesPage() {
  const queryClient = useQueryClient();
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [classFilter, setClassFilter] = useState<string>("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const [scanIdFilter, setScanIdFilter] = useState<string>("all");
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(new Set(["manual"]));

  const { data: scans } = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.get<any[]>("/scans"),
  });

  const { data: summary } = useQuery({
    queryKey: ["findings", "summary"],
    queryFn: () => api.get<FindingsSummary>("/findings/summary"),
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

  const [actionError, setActionError] = useState<string | null>(null);
  const [acceptingFinding, setAcceptingFinding] = useState<FindingOut | null>(null);

  /**
   * Opening a task derives its due date from the organization's SLA policy —
   * shorter for findings CISA lists as exploited, because observed exploitation
   * outranks theoretical severity.
   */
  const openRemediationTask = useMutation({
    mutationFn: (findingId: string) =>
      api.post("/remediation/tasks", { finding_id: findingId }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      queryClient.invalidateQueries({ queryKey: ["remediation-tasks"] });
      setActionError(null);
    },
    onError: (err: Error) => setActionError(err.message),
  });

  const acceptRisk = useMutation({
    mutationFn: (body: { finding_id: string; reason: string; expires_at: string }) =>
      api.post("/remediation/risk-acceptances", body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      queryClient.invalidateQueries({ queryKey: ["risk-acceptances"] });
      setAcceptingFinding(null);
      setActionError(null);
    },
    onError: (err: Error) => setActionError(err.message),
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

  const toggleGroupFindings = (groupFindings: FindingOut[]) => {
    if (!groupFindings || groupFindings.length === 0) return;
    const groupFindingIds = groupFindings.map(f => f.id);
    const allSelected = groupFindingIds.every(id => selectedFindingIds.has(id));
    
    const newSet = new Set(selectedFindingIds);
    if (allSelected) {
      groupFindingIds.forEach(id => newSet.delete(id));
    } else {
      groupFindingIds.forEach(id => newSet.add(id));
    }
    setSelectedFindingIds(newSet);
  };

  const toggleFolder = (folderId: string) => {
    const newSet = new Set(expandedFolders);
    if (newSet.has(folderId)) newSet.delete(folderId);
    else newSet.add(folderId);
    setExpandedFolders(newSet);
  };

  const filtered = useMemo(() => {
    if (!findings) return [];
    return findings
      .filter((f) => severityFilter === "all" || f.severity === severityFilter)
      .filter((f) => statusFilter === "all" || f.status === statusFilter)
      .filter((f) => classFilter === "all" || f.finding_class === classFilter)
      .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  }, [findings, severityFilter, statusFilter, classFilter]);

  const groupedFindings = useMemo(() => {
    if (!filtered) return {};
    const groups: Record<string, FindingOut[]> = { manual: [] };
    
    if (scans) {
      scans.filter(s => s.status === "completed").forEach(s => {
        groups[s.id] = [];
      });
    }

    filtered.forEach(f => {
      const key = f.scan_job_id || "manual";
      if (!groups[key]) groups[key] = [];
      groups[key].push(f);
    });
    return groups;
  }, [filtered, scans]);

  return (
    <>
      <Topbar title="Findings" />
      <main className="flex-1 space-y-4 overflow-y-auto p-6">
        {summary && summary.total_open > 0 && (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            {CLASS_OPTIONS.map((klass) => (
              <button
                key={klass}
                onClick={() => setClassFilter(classFilter === klass ? "all" : klass)}
                className={`rounded-xl border p-3 text-left transition-colors ${
                  classFilter === klass
                    ? "border-primary bg-primary/10"
                    : "border-border bg-surface hover:border-primary/40"
                }`}
              >
                <p className="text-[10px] font-bold uppercase tracking-widest text-muted">
                  {klass}
                </p>
                <p className="mt-1 font-mono text-2xl font-bold text-ink">
                  {summary.open_by_class[klass] ?? 0}
                </p>
              </button>
            ))}
          </div>
        )}

        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-3">
            <FilterSelect label="Severity" value={severityFilter} onChange={setSeverityFilter}
              options={["all", "critical", "high", "medium", "low", "info"]} />
            <FilterSelect label="Status" value={statusFilter} onChange={setStatusFilter}
              options={["all", ...STATUS_OPTIONS]} />
            <FilterSelect label="Class" value={classFilter} onChange={setClassFilter}
              options={["all", ...CLASS_OPTIONS]} />
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

          <div className="flex gap-2">
            {selectedFindingIds.size > 0 && (
              <button
                className="rounded border border-critical/50 bg-critical/10 px-3 py-1.5 text-xs font-medium tracking-wide text-critical hover:bg-critical/20"
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
        </div>

        <div className="space-y-4">
          {isLoading && <Card className="p-6"><p className="text-sm text-muted">Loading findings…</p></Card>}
          {isError && <Card className="p-6"><p className="text-sm text-critical">Unable to load findings from the API.</p></Card>}
          {findings && findings.length === 0 && (
            <Card className="p-6">
              <p className="text-sm text-muted">
                No findings recorded. Findings appear here after a scan observes something, or
                when one is entered manually — nothing is shown until real assessment data exists.
              </p>
            </Card>
          )}

          {filtered.length > 0 && (
            <>
              {Object.entries(groupedFindings).map(([groupId, groupFindings]) => {
                const isManual = groupId === "manual";
                const scan = scans?.find(s => s.id === groupId);
                
                if (!isManual && !scan) return null;
                if (isManual && groupFindings.length === 0 && (scans?.filter(s => s.status === "completed").length || 0) > 0) return null;

                const isExpanded = expandedFolders.has(groupId);
                const title = isManual ? "Manual / Uncategorized Findings" : `Scan Folder: ${scan.target_cidr} (${new Date(scan.created_at).toLocaleDateString()})`;
                const allSelected = groupFindings.length > 0 && groupFindings.every(f => selectedFindingIds.has(f.id));

                return (
                  <Card key={groupId} className="overflow-hidden p-0 transition-all">
                    <div 
                      className="flex cursor-pointer items-center justify-between border-b border-border px-5 py-3 bg-surface-hover/50 transition-colors hover:bg-surface-hover/80"
                      onClick={() => toggleFolder(groupId)}
                    >
                      <div className="flex items-center gap-3">
                        <Folder size={18} className="text-primary" />
                        <span className="text-sm font-medium text-ink">{title}</span>
                        <Badge label={`${groupFindings.length} finding(s)`} />
                      </div>
                      <div className="flex items-center gap-3">
                        {isExpanded ? <ChevronDown size={18} className="text-muted" /> : <ChevronRight size={18} className="text-muted" />}
                      </div>
                    </div>

                    {isExpanded && groupFindings.length === 0 && (
                      <p className="p-6 text-sm text-muted">No vulnerabilities found in this scan.</p>
                    )}

                    {isExpanded && groupFindings.length > 0 && (
                      <div className="divide-y divide-border/60">
                        <div className="flex items-center gap-3 border-b border-border bg-surface-hover/30 px-5 py-2">
                          <input
                            type="checkbox"
                            className="h-4 w-4 rounded border-border text-primary focus:ring-primary/40"
                            checked={allSelected}
                            onChange={() => toggleGroupFindings(groupFindings)}
                          />
                          <span className="text-xs uppercase tracking-wide text-muted font-medium">Select All</span>
                        </div>
                        {groupFindings.map((f) => (
                          <div key={f.id} className="p-4 hover:bg-surface-hover/40 transition-colors">
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
                                      <div className="mt-1 flex flex-wrap items-center gap-1.5">
                                        <span
                                          className={`rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider ${
                                            CLASS_STYLES[f.finding_class] ?? CLASS_STYLES.informational
                                          }`}
                                        >
                                          {f.finding_class}
                                        </span>
                                        <span
                                          title={CONFIDENCE_HINTS[f.confidence]}
                                          className="cursor-help rounded border border-border px-1.5 py-0.5 text-[9px] uppercase tracking-wider text-muted"
                                        >
                                          {f.confidence}
                                        </span>
                                        <span className="text-[11px] text-muted">
                                          {f.cve_id ? `${f.cve_id} · ` : ""}
                                          {f.cvss_score != null ? `CVSS ${f.cvss_score} · ` : ""}
                                          {f.source}
                                          {f.first_seen && ` · open ${formatDistanceToNow(new Date(f.first_seen))}`}
                                          {f.occurrence_count > 1 && ` · seen ${f.occurrence_count}×`}
                                        </span>
                                      </div>
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
                                      className="ml-2 rounded-md p-1.5 text-muted hover:bg-critical/10 hover:text-critical"
                                      title="Delete Vulnerability"
                                    >
                                      <Trash2 size={15} />
                                    </button>
                                  </div>
                                </div>

                                {expandedId === f.id && (
                                  <div className="ml-7 mt-3 space-y-3 rounded-lg bg-surface-hover/40 p-3 text-sm border border-border/50">
                                    <p className="text-ink/80">{f.description}</p>
                                    {f.evidence && (
                                      <div>
                                        <p className="mb-1 text-xs font-medium uppercase tracking-wide text-muted">
                                          Evidence
                                        </p>
                                        <pre className="max-h-48 overflow-auto whitespace-pre-wrap rounded border border-border/50 bg-ink/90 p-2 font-mono text-[11px] leading-relaxed text-white/80">
{f.evidence}
                                        </pre>
                                      </div>
                                    )}
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
                                    <div className="flex flex-wrap items-center gap-2 border-t border-border/50 pt-3">
                                      <button
                                        type="button"
                                        onClick={() => openRemediationTask.mutate(f.id)}
                                        disabled={openRemediationTask.isPending}
                                        className="rounded-md border border-primary/40 bg-primary/10 px-3 py-1.5 text-xs font-medium text-primary transition-colors hover:bg-primary/20 disabled:opacity-50"
                                      >
                                        Open remediation task
                                      </button>
                                      <button
                                        type="button"
                                        onClick={() => { setActionError(null); setAcceptingFinding(f); }}
                                        className="rounded-md border border-border px-3 py-1.5 text-xs font-medium text-muted transition-colors hover:border-primary/40 hover:text-ink"
                                      >
                                        Accept risk
                                      </button>
                                      {actionError && (
                                        <span className="text-xs text-critical">{actionError}</span>
                                      )}
                                    </div>

                                    <div className="flex items-center gap-2 pt-2 border-t border-border/50">
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
                );
              })}
            </>
          )}
        </div>
      </main>

      <Modal
        open={acceptingFinding !== null}
        onClose={() => setAcceptingFinding(null)}
        title="Accept this risk"
      >
        <AcceptRiskForm
          findingTitle={acceptingFinding?.title ?? ""}
          error={actionError}
          pending={acceptRisk.isPending}
          onSubmit={(reason, expiresAt) =>
            acceptingFinding &&
            acceptRisk.mutate({
              finding_id: acceptingFinding.id,
              reason,
              expires_at: expiresAt,
            })
          }
        />
      </Modal>
    </>
  );
}

function AcceptRiskForm({
  findingTitle, error, pending, onSubmit,
}: {
  findingTitle: string;
  error: string | null;
  pending: boolean;
  onSubmit: (reason: string, expiresAt: string) => void;
}) {
  const defaultExpiry = new Date();
  defaultExpiry.setDate(defaultExpiry.getDate() + 90);

  const [reason, setReason] = useState("");
  const [expiresAt, setExpiresAt] = useState(defaultExpiry.toISOString().slice(0, 10));

  const tomorrow = new Date();
  tomorrow.setDate(tomorrow.getDate() + 1);

  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit(reason, expiresAt);
      }}
    >
      <p className="text-sm text-muted">
        Recording a decision to live with{" "}
        <span className="font-medium text-ink">{findingTitle}</span> until a stated date.
      </p>

      <div>
        <label className="mb-1 block text-xs font-medium text-muted">Reason</label>
        <textarea
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          required
          rows={3}
          placeholder="Legacy application; replacement scheduled for Q4."
          className="w-full rounded-md border border-border bg-surface-hover px-3 py-2 text-sm text-ink focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
        />
      </div>

      <div>
        <label className="mb-1 block text-xs font-medium text-muted">Expires on</label>
        <input
          type="date"
          value={expiresAt}
          min={tomorrow.toISOString().slice(0, 10)}
          onChange={(e) => setExpiresAt(e.target.value)}
          required
          className="w-full rounded-md border border-border bg-surface-hover px-3 py-2 text-sm text-ink focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
        />
        <p className="mt-1 text-[11px] leading-relaxed text-muted/80">
          Required. When this date passes the acceptance expires automatically and the finding
          reopens — an acceptance with no end date is indistinguishable from having forgotten
          about it. Your account is recorded as the approver.
        </p>
      </div>

      {error && <p className="text-sm text-critical">{error}</p>}
      <Button type="submit" disabled={!reason.trim() || pending} className="w-full">
        {pending ? "Recording…" : "Record acceptance"}
      </Button>
    </form>
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
