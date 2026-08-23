"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle, ChevronDown, ChevronRight, Info, Loader2, Route, Waypoints,
} from "lucide-react";
import { api, ApiError, errorMessage } from "@/lib/api";
import { cn } from "@/lib/utils";

/**
 * Attack paths.
 *
 * The single most important thing on this page is the claim-strength label, and
 * it is deliberately impossible to miss. Every path the platform computes is
 * POTENTIAL: the relationships composing the route exist in the inventory, and
 * nothing has been attempted along it. There is no exploit verification in this
 * product, so nothing here has been demonstrated.
 *
 * The previous version showed a bare `is_verified: false` boolean and described
 * its output as "identified attack paths". A boolean cannot express "observed
 * but not verified", and `false` reads as "not yet checked" rather than
 * "theoretical".
 */

interface PathNode {
  id: string;
  type: string;
  name: string;
  severity?: string;
  confidence?: string;
  cve_id?: string | null;
  criticality?: string;
  internet_facing?: boolean;
}

interface RiskContributor {
  name: string;
  points: number;
  detail?: string;
}

interface AttackPath {
  id: string;
  claim_strength: "potential" | "observed" | "verified";
  claim_meaning: string;
  entry_point: string;
  risk_score: number;
  risk_breakdown: {
    score?: number;
    contributors?: RiskContributor[];
    model?: string;
    unavailable_factors?: { name: string; reason: string }[];
  };
  path_nodes: PathNode[];
  path_edges: string[];
  hop_count: number;
  verified_by_scan_job_id: string | null;
  evidence_note: string;
  last_computed_at: string | null;
}

interface AttackPathResponse {
  paths: AttackPath[];
  counts_by_claim_strength: Record<string, number>;
  disclaimer: string;
  empty_state_note: string;
}

const CLAIM_STYLE: Record<string, string> = {
  potential: "border-sky-500/30 bg-sky-500/10 text-sky-400",
  observed: "border-amber-500/30 bg-amber-500/10 text-amber-400",
  verified: "border-red-500/30 bg-red-500/10 text-red-400",
};

const SEVERITY_TONE: Record<string, string> = {
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
  info: "text-info",
};

function riskTone(score: number): string {
  if (score >= 70) return "text-critical";
  if (score >= 45) return "text-high";
  if (score >= 20) return "text-medium";
  return "text-muted";
}

function PathRow({ path }: { path: AttackPath }) {
  const [open, setOpen] = useState(false);
  const contributors = path.risk_breakdown?.contributors ?? [];

  return (
    <div className="border-b border-border/60 last:border-0">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        className="flex w-full items-start gap-4 px-5 py-4 text-left hover:bg-surface-hover"
      >
        {open ? (
          <ChevronDown className="mt-1 h-4 w-4 shrink-0 text-muted" />
        ) : (
          <ChevronRight className="mt-1 h-4 w-4 shrink-0 text-muted" />
        )}

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={cn(
                "rounded-md border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider",
                CLAIM_STYLE[path.claim_strength] ?? CLAIM_STYLE.potential,
              )}
            >
              {path.claim_strength}
            </span>
            <span className="text-[11px] text-muted">
              {path.hop_count} hop{path.hop_count === 1 ? "" : "s"} ·{" "}
              {path.entry_point === "internet"
                ? "from the internet"
                : "from an adjacent network"}
            </span>
          </div>

          <div className="mt-2 flex flex-wrap items-center gap-1.5 text-sm">
            {path.path_nodes.map((node, index) => (
              <span key={`${node.id}-${index}`} className="flex items-center gap-1.5">
                {index > 0 && <span className="text-muted">→</span>}
                <span
                  className={cn(
                    "rounded-md bg-surface-hover px-2 py-1 text-xs",
                    node.severity
                      ? SEVERITY_TONE[node.severity] ?? "text-ink"
                      : "text-ink",
                  )}
                  title={node.type}
                >
                  {node.name}
                </span>
              </span>
            ))}
          </div>
        </div>

        <div className="shrink-0 text-right">
          <div className={cn("text-lg font-bold", riskTone(path.risk_score))}>
            {path.risk_score.toFixed(0)}
          </div>
          <div className="text-[10px] uppercase tracking-wider text-muted">risk</div>
        </div>
      </button>

      {open && (
        <div className="space-y-4 border-t border-border/60 bg-surface-hover/30 px-5 py-4">
          <p className="text-xs text-ink/90">{path.claim_meaning}</p>

          <div>
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-muted">
              How this score is made up
            </h4>
            {contributors.length === 0 ? (
              <p className="mt-1 text-xs text-muted">No contributors recorded.</p>
            ) : (
              <ul className="mt-2 space-y-1">
                {contributors.map((item, index) => (
                  <li
                    key={index}
                    className="flex items-baseline justify-between gap-4 text-xs"
                  >
                    <span className="text-ink/90">
                      {item.name}
                      {item.detail && (
                        <span className="ml-1 text-muted">— {item.detail}</span>
                      )}
                    </span>
                    <span
                      className={cn(
                        "shrink-0 font-mono",
                        item.points < 0 ? "text-emerald-400" : "text-ink",
                      )}
                    >
                      {item.points > 0 ? "+" : ""}
                      {item.points}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {(path.risk_breakdown?.unavailable_factors ?? []).length > 0 && (
            <div>
              <h4 className="text-[11px] font-semibold uppercase tracking-wider text-muted">
                Not accounted for
              </h4>
              <ul className="mt-1 space-y-1">
                {path.risk_breakdown.unavailable_factors!.map((factor) => (
                  <li key={factor.name} className="text-[11px] text-muted">
                    <span className="text-ink/80">{factor.name}</span> — {factor.reason}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {path.evidence_note && (
            <p className="text-xs text-ink/90">{path.evidence_note}</p>
          )}
        </div>
      )}
    </div>
  );
}

export default function AttackPathsPage() {
  const { data, isLoading, error } = useQuery<AttackPathResponse>({
    queryKey: ["attack-paths"],
    queryFn: () => api.get<AttackPathResponse>("/attack-paths/"),
  });

  const paths = data?.paths ?? [];
  const counts = data?.counts_by_claim_strength ?? {};

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="flex items-center gap-3 text-3xl font-bold tracking-tight text-ink">
          <Waypoints className="h-8 w-8 text-primary" />
          Attack Paths
        </h1>
        <p className="mt-2 text-muted">
          Routes through your recorded inventory by which an attacker could
          plausibly reach an open finding.
        </p>
      </div>

      {data?.disclaimer && (
        <div className="flex items-start gap-3 rounded-xl border border-sky-500/30 bg-sky-500/5 p-4">
          <Info className="mt-0.5 h-5 w-5 shrink-0 text-sky-400" />
          <p className="text-sm text-ink/90">{data.disclaimer}</p>
        </div>
      )}

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-400">
          <AlertTriangle className="h-5 w-5" />
          {errorMessage(error, "Attack paths could not be loaded.")}
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-3">
        {(["potential", "observed", "verified"] as const).map((strength) => (
          <div key={strength} className="rounded-xl border border-border bg-surface p-5">
            <p className="text-xs font-medium uppercase tracking-wider text-muted">
              {strength}
            </p>
            <p className="mt-2 text-2xl font-bold text-ink">{counts[strength] ?? 0}</p>
          </div>
        ))}
      </div>

      <section className="rounded-xl border border-border bg-surface">
        <div className="flex items-center gap-2 border-b border-border px-5 py-4">
          <Route className="h-4 w-4 text-primary" />
          <h2 className="text-sm font-semibold text-ink">Routes, highest risk first</h2>
        </div>

        {isLoading ? (
          <div className="flex h-40 items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin text-muted" />
          </div>
        ) : paths.length === 0 ? (
          <div className="p-8 text-center text-sm text-muted">
            {data?.empty_state_note ||
              "No attack paths have been computed for this organization."}
          </div>
        ) : (
          paths.map((path) => <PathRow key={path.id} path={path} />)
        )}
      </section>
    </div>
  );
}
