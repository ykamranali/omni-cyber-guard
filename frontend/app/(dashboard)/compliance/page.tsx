"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle, CheckCircle2, ChevronDown, ChevronRight, FileCheck2,
  HelpCircle, Loader2, MinusCircle, Play, Plus, ShieldQuestion, XCircle,
} from "lucide-react";
import { api, ApiError, errorMessage } from "@/lib/api";
import { cn } from "@/lib/utils";

/**
 * Compliance.
 *
 * The page previously read `Framework[]` with a `coverage_percent` field from
 * `/compliance/frameworks`, which returns `{ frameworks: [...] }` and has no
 * such field — so nothing rendered correctly. Its only prose was inferred from
 * `coverage_percent < 100`: "Deficiencies detected. Some required controls lack
 * sufficient technical evidence" or "Fully Compliant. All tracked controls…",
 * neither of which was based on a single control result. "Configure Frameworks"
 * and "View Controls" had no handlers.
 *
 * The rule the backend enforces and this page has to show honestly: **absence
 * of evidence is never a pass**. A control that could not be evaluated is
 * NOT_ASSESSED, it is excluded from the compliance percentage, and it is not a
 * failure either. That is why two percentages are displayed rather than one.
 */

interface Assessment {
  id: string;
  started_at: string | null;
  completed_at: string | null;
  controls_total: number;
  controls_passed: number;
  controls_failed: number;
  controls_not_assessed: number;
  controls_not_applicable: number;
  controls_exception: number;
  compliance_percent: number | null;
  assessable_percent: number;
}

interface Framework {
  id: string;
  slug: string;
  name: string;
  version: string;
  description: string;
  source: string;
  control_count: number;
  last_assessed_at: string | null;
  assessment: Assessment | null;
  note: string | null;
}

interface Pack {
  slug: string;
  name: string;
  description: string;
  control_count: number;
  manual_control_count: number;
}

interface ControlResult {
  id: string;
  code: string;
  title: string;
  description: string;
  guidance: string;
  check_type: string;
  result: "pass" | "fail" | "not_assessed" | "not_applicable" | "exception";
  summary: string;
  evidence: Record<string, unknown>;
  assets_in_scope: number;
  assets_failing: number;
}

interface Requirement {
  id: string;
  code: string;
  title: string;
  description: string;
  controls: ControlResult[];
}

interface ResultsResponse {
  framework: { id: string; name: string; version?: string; source?: string };
  assessment: Assessment | null;
  requirements: Requirement[];
  note?: string;
}

const RESULT_STYLE: Record<string, { label: string; className: string; Icon: typeof CheckCircle2 }> = {
  pass: {
    label: "Pass",
    className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
    Icon: CheckCircle2,
  },
  fail: {
    label: "Fail",
    className: "border-red-500/30 bg-red-500/10 text-red-400",
    Icon: XCircle,
  },
  not_assessed: {
    label: "Not assessed",
    className: "border-amber-500/30 bg-amber-500/10 text-amber-400",
    Icon: ShieldQuestion,
  },
  not_applicable: {
    label: "Not applicable",
    className: "border-border bg-surface-hover text-muted",
    Icon: MinusCircle,
  },
  exception: {
    label: "Exception",
    className: "border-sky-500/30 bg-sky-500/10 text-sky-400",
    Icon: HelpCircle,
  },
};

function ControlRow({ control }: { control: ControlResult }) {
  const [open, setOpen] = useState(false);
  const style = RESULT_STYLE[control.result] ?? RESULT_STYLE.not_assessed;
  const { Icon } = style;

  return (
    <div className="border-b border-border/50 last:border-0">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        className="flex w-full items-start gap-3 px-4 py-3 text-left hover:bg-surface-hover/50"
      >
        {open ? (
          <ChevronDown className="mt-0.5 h-4 w-4 shrink-0 text-muted" />
        ) : (
          <ChevronRight className="mt-0.5 h-4 w-4 shrink-0 text-muted" />
        )}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <code className="text-xs text-muted">{control.code}</code>
            <span className="text-sm text-ink">{control.title}</span>
          </div>
          {control.summary && (
            <p className="mt-0.5 text-xs text-muted">{control.summary}</p>
          )}
        </div>
        <span
          className={cn(
            "inline-flex shrink-0 items-center gap-1.5 rounded-md border px-2 py-1 text-[11px] font-medium",
            style.className,
          )}
        >
          <Icon className="h-3.5 w-3.5" />
          {style.label}
        </span>
      </button>

      {open && (
        <div className="space-y-3 bg-surface-hover/30 px-11 py-3 text-xs">
          {control.description && <p className="text-ink/90">{control.description}</p>}
          {control.guidance && (
            <p className="text-muted">
              <span className="font-medium text-ink/80">How to satisfy it: </span>
              {control.guidance}
            </p>
          )}

          <div className="flex flex-wrap gap-4 text-[11px] text-muted">
            <span>Check type: {control.check_type.replace(/_/g, " ")}</span>
            {control.assets_in_scope > 0 && (
              <span>
                {control.assets_failing} of {control.assets_in_scope} asset(s) failing
              </span>
            )}
          </div>

          {Object.keys(control.evidence || {}).length > 0 && (
            <div>
              <p className="mb-1 font-medium text-ink/80">Evidence</p>
              <pre className="max-h-56 overflow-auto rounded-md bg-surface p-3 text-[11px] leading-relaxed text-ink/80">
                {JSON.stringify(control.evidence, null, 2)}
              </pre>
            </div>
          )}

          {control.result === "not_assessed" && (
            <p className="rounded-md border border-amber-500/30 bg-amber-500/5 p-2 text-amber-400">
              This control could not be evaluated, so it is excluded from the
              compliance percentage. It is not a pass and it is not a failure —
              absence of evidence is neither.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function AssessmentSummary({ assessment }: { assessment: Assessment }) {
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <div className="rounded-lg border border-border bg-surface p-4">
        <p className="text-[11px] uppercase tracking-wider text-muted">Compliance</p>
        <p className="mt-1 text-2xl font-bold text-ink">
          {assessment.compliance_percent === null
            ? "—"
            : `${assessment.compliance_percent.toFixed(0)}%`}
        </p>
        <p className="mt-1 text-[11px] text-muted">
          {assessment.compliance_percent === null
            ? "Nothing could be assessed."
            : "Of the controls that could be assessed."}
        </p>
      </div>

      <div className="rounded-lg border border-border bg-surface p-4">
        <p className="text-[11px] uppercase tracking-wider text-muted">Coverage</p>
        <p className="mt-1 text-2xl font-bold text-ink">
          {assessment.assessable_percent.toFixed(0)}%
        </p>
        <p className="mt-1 text-[11px] text-muted">
          How much of the framework this platform can evaluate automatically.
        </p>
      </div>

      <div className="rounded-lg border border-border bg-surface p-4">
        <p className="text-[11px] uppercase tracking-wider text-muted">Passed / failed</p>
        <p className="mt-1 text-2xl font-bold text-ink">
          <span className="text-emerald-400">{assessment.controls_passed}</span>
          <span className="text-muted"> / </span>
          <span className="text-red-400">{assessment.controls_failed}</span>
        </p>
      </div>

      <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4">
        <p className="text-[11px] uppercase tracking-wider text-amber-400">Not assessed</p>
        <p className="mt-1 text-2xl font-bold text-amber-400">
          {assessment.controls_not_assessed}
        </p>
        <p className="mt-1 text-[11px] text-ink/80">
          Excluded from the percentage above. Not passes.
        </p>
      </div>
    </div>
  );
}

export default function CompliancePage() {
  const queryClient = useQueryClient();
  const [expanded, setExpanded] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const { data: frameworkData, isLoading } = useQuery<{ frameworks: Framework[] }>({
    queryKey: ["compliance", "frameworks"],
    queryFn: () => api.get<{ frameworks: Framework[] }>("/compliance/frameworks"),
  });

  const { data: packData } = useQuery<{ packs: Pack[]; note: string }>({
    queryKey: ["compliance", "packs"],
    queryFn: () => api.get<{ packs: Pack[]; note: string }>("/compliance/packs"),
  });

  const { data: results, isFetching: loadingResults } = useQuery<ResultsResponse>({
    queryKey: ["compliance", "results", expanded],
    queryFn: () => api.get<ResultsResponse>(`/compliance/frameworks/${expanded}/results`),
    enabled: Boolean(expanded),
  });

  const install = useMutation({
    mutationFn: (slug: string) => api.post(`/compliance/packs/${slug}/install`, {}),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["compliance"] });
      setError(null);
    },
    onError: (caught) =>
      setError(errorMessage(caught, "The pack could not be installed.")),
  });

  const assess = useMutation({
    mutationFn: (id: string) => api.post(`/compliance/frameworks/${id}/assess`, {}),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["compliance"] });
      setError(null);
    },
    onError: (caught) =>
      setError(
        errorMessage(caught, "The assessment could not be run."),
      ),
  });

  const frameworks = frameworkData?.frameworks ?? [];
  const installedSlugs = new Set(frameworks.map((framework) => framework.slug));
  const availablePacks = (packData?.packs ?? []).filter(
    (pack) => !installedSlugs.has(pack.slug),
  );

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="flex items-center gap-3 text-3xl font-bold tracking-tight text-ink">
          <FileCheck2 className="h-8 w-8 text-primary" />
          Compliance
        </h1>
        <p className="mt-2 text-muted">
          Control results derived from the evidence this platform has actually
          collected.
        </p>
      </div>

      {error && (
        <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/5 px-4 py-3 text-sm text-red-400">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span className="flex-1">{error}</span>
          <button type="button" onClick={() => setError(null)} className="text-xs underline">
            dismiss
          </button>
        </div>
      )}

      {availablePacks.length > 0 && (
        <section className="rounded-xl border border-border bg-surface p-5">
          <h2 className="text-sm font-semibold text-ink">Available control sets</h2>
          {packData?.note && (
            <p className="mt-1 max-w-3xl text-xs leading-relaxed text-muted">
              {packData.note}
            </p>
          )}

          <div className="mt-4 grid gap-3 md:grid-cols-3">
            {availablePacks.map((pack) => (
              <div key={pack.slug} className="rounded-lg border border-border bg-background p-4">
                <h3 className="text-sm font-medium text-ink">{pack.name}</h3>
                <p className="mt-1 text-xs text-muted">{pack.description}</p>
                <p className="mt-2 text-[11px] text-muted">
                  {pack.control_count} control(s)
                  {pack.manual_control_count > 0 && (
                    <>
                      {" · "}
                      <span className="text-amber-400">
                        {pack.manual_control_count} need manual attestation
                      </span>
                    </>
                  )}
                </p>
                <button
                  type="button"
                  onClick={() => install.mutate(pack.slug)}
                  disabled={install.isPending}
                  className="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs text-ink hover:bg-surface-hover disabled:opacity-40"
                >
                  {install.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Plus className="h-3.5 w-3.5" />
                  )}
                  Install
                </button>
              </div>
            ))}
          </div>
        </section>
      )}

      {isLoading ? (
        <div className="flex h-40 items-center justify-center">
          <Loader2 className="h-6 w-6 animate-spin text-muted" />
        </div>
      ) : frameworks.length === 0 ? (
        <div className="rounded-xl border border-dashed border-border bg-surface p-10 text-center">
          <FileCheck2 className="mx-auto h-10 w-10 text-muted/40" />
          <p className="mt-3 text-sm text-ink/80">No control sets installed</p>
          <p className="mx-auto mt-1 max-w-md text-xs leading-relaxed text-muted">
            Install one above to start assessing. Nothing is assumed compliant
            until a control has been evaluated against real evidence.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {frameworks.map((framework) => {
            const open = expanded === framework.id;
            return (
              <section
                key={framework.id}
                className="overflow-hidden rounded-xl border border-border bg-surface"
              >
                <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border px-5 py-4">
                  <div className="min-w-0">
                    <h2 className="text-base font-semibold text-ink">
                      {framework.name}
                      {framework.version && (
                        <span className="ml-2 text-xs font-normal text-muted">
                          {framework.version}
                        </span>
                      )}
                    </h2>
                    {framework.description && (
                      <p className="mt-1 max-w-3xl text-xs text-muted">
                        {framework.description}
                      </p>
                    )}
                    <p className="mt-1 text-[11px] text-muted">
                      {framework.control_count} control(s) ·{" "}
                      {framework.last_assessed_at
                        ? `last assessed ${new Date(framework.last_assessed_at).toLocaleString()}`
                        : "never assessed"}
                    </p>
                  </div>

                  <div className="flex shrink-0 gap-2">
                    <button
                      type="button"
                      onClick={() => assess.mutate(framework.id)}
                      disabled={assess.isPending}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground disabled:opacity-50"
                    >
                      {assess.isPending ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <Play className="h-3.5 w-3.5" />
                      )}
                      Run assessment
                    </button>
                    <button
                      type="button"
                      onClick={() => setExpanded(open ? null : framework.id)}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs text-ink hover:bg-surface-hover"
                    >
                      {open ? "Hide controls" : "View controls"}
                    </button>
                  </div>
                </div>

                <div className="p-5">
                  {framework.assessment ? (
                    <AssessmentSummary assessment={framework.assessment} />
                  ) : (
                    <div className="flex items-start gap-3 rounded-lg border border-amber-500/30 bg-amber-500/5 p-4">
                      <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" />
                      <p className="text-sm text-ink/90">
                        {framework.note ||
                          "This framework has never been assessed. An unassessed framework is not a compliant one."}
                      </p>
                    </div>
                  )}
                </div>

                {open && (
                  <div className="border-t border-border">
                    {loadingResults ? (
                      <div className="flex h-32 items-center justify-center">
                        <Loader2 className="h-5 w-5 animate-spin text-muted" />
                      </div>
                    ) : results?.requirements?.length ? (
                      results.requirements.map((requirement) => (
                        <div key={requirement.id}>
                          <div className="bg-surface-hover/40 px-5 py-2">
                            <p className="text-xs font-semibold uppercase tracking-wider text-muted">
                              {requirement.code} — {requirement.title}
                            </p>
                          </div>
                          {requirement.controls.map((control) => (
                            <ControlRow key={control.id} control={control} />
                          ))}
                        </div>
                      ))
                    ) : (
                      <p className="p-6 text-center text-sm text-muted">
                        {results?.note || "No control results yet."}
                      </p>
                    )}
                  </div>
                )}
              </section>
            );
          })}
        </div>
      )}
    </div>
  );
}
