"use client";

import { useState } from "react";
import {
  AlertTriangle, CheckCircle2, Loader2, Plug, RefreshCw, XCircle,
} from "lucide-react";
import { ApiError } from "@/lib/api";
import { cn } from "@/lib/utils";

/**
 * The state of one external integration, and the controls for it.
 *
 * This component exists because "no rows" and "no integration" look identical
 * on a page that only lists rows, and the difference is the whole story. The
 * previous cloud and identity pages resolved that ambiguity in the worst
 * possible way: the backend wrote a fake resource named "Discovery Failed: no
 * credentials" into the inventory so the table had something in it.
 *
 * Now the API returns each adapter's real state — configured or not, what is
 * missing, when it last ran, how many records it read — and this renders it
 * plainly.
 */

export interface IntegrationState {
  provider: string;
  configured: boolean;
  missing: string[];
  why_required: string;
  how_to_enable: string;
  implemented_in: string;
  status: string;
  message: string;
  last_attempt_at: string | null;
  last_success_at: string | null;
  records_discovered: number;
}

const STATUS_STYLE: Record<string, { label: string; className: string; Icon: typeof Plug }> = {
  connected: {
    label: "Connected",
    className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
    Icon: CheckCircle2,
  },
  error: {
    label: "Last attempt failed",
    className: "border-red-500/30 bg-red-500/10 text-red-400",
    Icon: XCircle,
  },
  not_configured: {
    label: "Not configured",
    className: "border-amber-500/30 bg-amber-500/10 text-amber-400",
    Icon: AlertTriangle,
  },
  never_run: {
    label: "Configured, never run",
    className: "border-sky-500/30 bg-sky-500/10 text-sky-400",
    Icon: Plug,
  },
};

function when(value: string | null): string {
  if (!value) return "never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "never";
  return date.toLocaleString();
}

export function IntegrationPanel({
  integrations,
  onRun,
  runLabel = "Read now",
  emptyNote,
}: {
  integrations: IntegrationState[];
  onRun: (provider: string) => Promise<void>;
  runLabel?: string;
  emptyNote?: string;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const run = async (provider: string) => {
    setBusy(provider);
    setErrors((previous) => ({ ...previous, [provider]: "" }));
    try {
      await onRun(provider);
    } catch (caught) {
      const detail =
        caught instanceof ApiError
          ? caught.message
          : "The request did not complete.";
      setErrors((previous) => ({ ...previous, [provider]: detail }));
    } finally {
      setBusy(null);
    }
  };

  if (integrations.length === 0) {
    return (
      <div className="rounded-xl border border-border bg-surface p-5 text-sm text-muted">
        {emptyNote || "No integrations are available for this data source."}
      </div>
    );
  }

  return (
    <div className="grid gap-4 md:grid-cols-2">
      {integrations.map((integration) => {
        const style = STATUS_STYLE[integration.status] ?? STATUS_STYLE.not_configured;
        const { Icon } = style;
        const open = expanded[integration.provider];

        return (
          <div
            key={integration.provider}
            className="rounded-xl border border-border bg-surface p-5"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <h3 className="text-sm font-semibold text-ink">{integration.provider}</h3>
                <div
                  className={cn(
                    "mt-2 inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[11px] font-medium",
                    style.className,
                  )}
                >
                  <Icon className="h-3.5 w-3.5" />
                  {style.label}
                </div>
              </div>

              <button
                type="button"
                onClick={() => run(integration.provider)}
                disabled={!integration.configured || busy === integration.provider}
                title={
                  integration.configured
                    ? undefined
                    : "Configure this integration before it can read anything."
                }
                className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs font-medium text-ink transition-colors hover:bg-surface-hover disabled:cursor-not-allowed disabled:opacity-40"
              >
                {busy === integration.provider ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <RefreshCw className="h-3.5 w-3.5" />
                )}
                {runLabel}
              </button>
            </div>

            {integration.configured && (
              <dl className="mt-4 grid grid-cols-2 gap-2 text-[11px]">
                <div>
                  <dt className="text-muted">Last attempt</dt>
                  <dd className="text-ink">{when(integration.last_attempt_at)}</dd>
                </div>
                <div>
                  <dt className="text-muted">Last success</dt>
                  <dd className="text-ink">{when(integration.last_success_at)}</dd>
                </div>
                <div>
                  <dt className="text-muted">Records read</dt>
                  <dd className="text-ink">{integration.records_discovered}</dd>
                </div>
              </dl>
            )}

            {integration.message && (
              <p className="mt-3 whitespace-pre-wrap text-xs text-muted">
                {integration.message}
              </p>
            )}

            {errors[integration.provider] && (
              <p className="mt-3 text-xs text-red-400">{errors[integration.provider]}</p>
            )}

            {!integration.configured && (
              <div className="mt-4 border-t border-border pt-3">
                <p className="text-xs text-ink/90">{integration.why_required}</p>

                {integration.missing.length > 0 && (
                  <p className="mt-2 text-[11px] text-muted">
                    Missing:{" "}
                    {integration.missing.map((name) => (
                      <code key={name} className="mr-1.5 text-ink/80">
                        {name}
                      </code>
                    ))}
                  </p>
                )}

                <button
                  type="button"
                  onClick={() =>
                    setExpanded((previous) => ({
                      ...previous,
                      [integration.provider]: !previous[integration.provider],
                    }))
                  }
                  className="mt-2 text-[11px] font-medium text-primary hover:underline"
                >
                  {open ? "Hide setup steps" : "How do I enable this?"}
                </button>

                {open && (
                  <>
                    <pre className="mt-2 overflow-x-auto rounded-md bg-surface-hover p-3 text-[11px] leading-relaxed text-ink/80">
                      {integration.how_to_enable}
                    </pre>
                    <p className="mt-2 text-[10px] text-muted">
                      Implemented in <code>{integration.implemented_in}</code>
                    </p>
                  </>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
