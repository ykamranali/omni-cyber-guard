"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Activity, AlertTriangle, CheckCircle2, Download, FileBarChart2, Loader2,
  ShieldCheck,
} from "lucide-react";
import { api, ApiError, errorMessage } from "@/lib/api";
import { cn } from "@/lib/utils";

/**
 * Report downloads.
 *
 * Two things were broken and one was misleading.
 *
 * The download called `fetch("/api/v1/reports/…")` with **no second argument** —
 * no Authorization header at all — against a path relative to the frontend
 * origin. It could not have worked on any deployment. It now goes through
 * `api.download`, which attaches the bearer token, handles 401 by signing the
 * user out, and surfaces the API's own error detail.
 *
 * And the cards each carried a static "Latest Snapshot" label with nothing
 * behind it. The panel now shows what the report will actually contain, read
 * from the same figures the document is built from — so an operator can tell
 * before downloading whether there is anything in it.
 */

interface DashboardSummary {
  total_assets: number;
  open_findings: number;
  findings_by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  completed_scans: number;
  last_scan_at: string | null;
}

const REPORTS = [
  {
    id: "executive",
    title: "Executive Security Summary",
    description:
      "Assessment coverage, inventory size and open findings by severity, with the counting rules stated on the document.",
    audience: "Leadership and board",
    icon: ShieldCheck,
    accent: "text-emerald-400",
    surface: "border-emerald-500/30 bg-emerald-500/5",
    path: "/reports/executive/pdf",
    filename: "Executive_Security_Report.pdf",
  },
  {
    id: "technical",
    title: "Technical Vulnerability Report",
    description:
      "Every open finding with its class, confidence, source, CVE reference and the verbatim scanner evidence behind it.",
    audience: "Engineering and remediation owners",
    icon: Activity,
    accent: "text-sky-400",
    surface: "border-sky-500/30 bg-sky-500/5",
    path: "/reports/technical/pdf",
    filename: "Technical_Vulnerability_Report.pdf",
  },
] as const;

export default function ReportsPage() {
  const [busy, setBusy] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [done, setDone] = useState<Record<string, boolean>>({});

  const { data: summary } = useQuery<DashboardSummary>({
    queryKey: ["dashboard", "summary"],
    queryFn: () => api.get<DashboardSummary>("/dashboard/summary"),
    retry: false,
  });

  const run = async (report: (typeof REPORTS)[number]) => {
    setBusy(report.id);
    setErrors((previous) => ({ ...previous, [report.id]: "" }));
    setDone((previous) => ({ ...previous, [report.id]: false }));

    const stamp = new Date().toISOString().slice(0, 10);
    try {
      await api.download(report.path, report.filename.replace(".pdf", `_${stamp}.pdf`));
      setDone((previous) => ({ ...previous, [report.id]: true }));
    } catch (caught) {
      setErrors((previous) => ({
        ...previous,
        [report.id]:
          errorMessage(caught, "The download did not complete."),
      }));
    } finally {
      setBusy(null);
    }
  };

  const noAssessment = (summary?.completed_scans ?? 0) === 0;

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="flex items-center gap-3 text-3xl font-bold tracking-tight text-ink">
          <FileBarChart2 className="h-8 w-8 text-primary" />
          Reports
        </h1>
        <p className="mt-2 text-muted">
          Generated from your live data at the moment you download them. Nothing
          is pre-rendered or cached.
        </p>
      </div>

      {noAssessment && (
        <div className="flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/5 p-4">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" />
          <div className="text-sm">
            <p className="font-medium text-amber-400">No completed assessment yet</p>
            <p className="mt-1 text-ink/90">
              These reports will still generate, and will say so on the first
              page. A report of zero findings from zero scans is not a clean
              result — it means nothing has been assessed.
            </p>
          </div>
        </div>
      )}

      {summary && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { label: "Completed assessments", value: summary.completed_scans ?? 0 },
            { label: "Assets in inventory", value: summary.total_assets ?? 0 },
            { label: "Open findings", value: summary.open_findings ?? 0 },
            { label: "Critical", value: summary.findings_by_severity?.critical ?? 0 },
          ].map((item) => (
            <div key={item.label} className="rounded-xl border border-border bg-surface p-5">
              <p className="text-xs font-medium uppercase tracking-wider text-muted">
                {item.label}
              </p>
              <p className="mt-2 text-2xl font-bold text-ink">{item.value}</p>
            </div>
          ))}
        </div>
      )}

      <div className="grid gap-5 lg:grid-cols-2">
        {REPORTS.map((report) => {
          const { icon: Icon } = report;
          return (
            <div
              key={report.id}
              className={cn(
                "flex flex-col rounded-xl border p-6",
                report.surface,
              )}
            >
              <div className="flex items-start gap-4">
                <div
                  className={cn(
                    "flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-border bg-surface",
                    report.accent,
                  )}
                >
                  <Icon className="h-5 w-5" />
                </div>
                <div className="min-w-0">
                  <h2 className="text-base font-semibold text-ink">{report.title}</h2>
                  <p className="mt-0.5 text-[11px] uppercase tracking-wider text-muted">
                    {report.audience}
                  </p>
                </div>
              </div>

              <p className="mt-4 flex-1 text-sm text-ink/90">{report.description}</p>

              {errors[report.id] && (
                <p className="mt-3 text-xs text-red-400">{errors[report.id]}</p>
              )}

              <button
                type="button"
                onClick={() => run(report)}
                disabled={busy === report.id}
                className="mt-5 inline-flex items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-50"
              >
                {busy === report.id ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Generating…
                  </>
                ) : done[report.id] ? (
                  <>
                    <CheckCircle2 className="h-4 w-4" />
                    Downloaded — generate again
                  </>
                ) : (
                  <>
                    <Download className="h-4 w-4" />
                    Download PDF
                  </>
                )}
              </button>
            </div>
          );
        })}
      </div>

      <p className="text-xs text-muted">
        Coverage is limited to what your completed assessments actually targeted.
        Anything outside their scope is unassessed, not clean — both documents
        state this.
      </p>
    </div>
  );
}
