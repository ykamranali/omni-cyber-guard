"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  AlertTriangle, BrainCircuit, Check, ChevronDown, ChevronRight,
  Database, Loader2, Send, ShieldAlert, ShieldCheck, Sparkles, User, X,
} from "lucide-react";
import { api, ApiError, errorMessage } from "@/lib/api";
import { cn } from "@/lib/utils";

/**
 * The security engineer.
 *
 * Two things this page deliberately does not do. It does not greet the
 * operator with a claim about what the assistant knows — the previous version
 * opened with "I have full context of your organization's attack surface",
 * which was untrue and unfalsifiable. And it does not show a permanent "LLM
 * Active" badge; the badge now reflects the configuration the API reports, so
 * a disabled assistant looks disabled.
 *
 * Every answer arrives with the records that were retrieved to support it and
 * the result of the grounding check. Both are rendered, because an assistant
 * that comments on security posture should be checkable rather than trusted.
 */

type GroundingStatus =
  | "grounded" | "rejected" | "no_evidence" | "unavailable" | "not_applicable";

interface ProviderStatus {
  configured: boolean;
  provider: string;
  endpoint: string;
  model: string;
  missing: string[];
  why_required: string;
  how_to_enable: string;
  implemented_in: string;
}

interface AgentStatus {
  provider: ProviderStatus;
  retrieval_tools: { name: string; description: string; required_permission: string }[];
  proposable_actions: { action_type: string; description: string; required_permission: string }[];
  guarantees: Record<string, boolean>;
}

interface Grounding {
  status: GroundingStatus;
  cited_references: string[];
  unsupported_references: string[];
  message: string;
  validated: string[];
  not_validated: string[];
  not_validated_note: string;
}

interface ToolCall {
  tool: string;
  arguments: Record<string, unknown>;
  row_count: number;
  error?: string;
}

interface Proposal {
  id: string;
  action_type: string;
  parameters: Record<string, unknown>;
  rationale: string;
  effect: string;
  required_permission: string;
  status: string;
  expires_at: string | null;
  result: Record<string, unknown>;
  error: string;
}

interface AgentResponse {
  available: boolean;
  answer: string;
  unavailable_reason: string;
  grounding: Grounding | null;
  evidence: Record<string, unknown>[];
  tool_calls: ToolCall[];
  conversation_id: string | null;
  message_id: string | null;
  proposals: Proposal[];
}

interface Turn {
  id: string;
  role: "user" | "assistant";
  content: string;
  response?: AgentResponse;
}

const GROUNDING_LABEL: Record<GroundingStatus, string> = {
  grounded: "Grounded in retrieved records",
  rejected: "Answer withheld — untraceable references",
  no_evidence: "No records retrieved",
  unavailable: "Model unavailable",
  not_applicable: "",
};

function GroundingBadge({ status }: { status: GroundingStatus }) {
  if (status === "not_applicable") return null;
  const grounded = status === "grounded";
  const rejected = status === "rejected";
  const Icon = grounded ? ShieldCheck : rejected ? ShieldAlert : AlertTriangle;
  return (
    <div
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[11px] font-medium",
        grounded && "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
        rejected && "border-red-500/30 bg-red-500/10 text-red-400",
        !grounded && !rejected && "border-amber-500/30 bg-amber-500/10 text-amber-400",
      )}
    >
      <Icon className="h-3.5 w-3.5" />
      {GROUNDING_LABEL[status]}
    </div>
  );
}

function EvidencePanel({ response }: { response: AgentResponse }) {
  const [open, setOpen] = useState(false);
  const rows = response.evidence ?? [];
  const calls = response.tool_calls ?? [];
  if (rows.length === 0 && calls.length === 0) return null;

  return (
    <div className="mt-3 rounded-lg border border-border bg-surface/60">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left text-xs font-medium text-muted hover:text-ink"
      >
        {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        <Database className="h-3.5 w-3.5" />
        Evidence — {rows.length} record{rows.length === 1 ? "" : "s"} from{" "}
        {calls.length} quer{calls.length === 1 ? "y" : "ies"}
      </button>

      {open && (
        <div className="space-y-3 border-t border-border px-3 py-3">
          <div className="space-y-1">
            {calls.map((call, index) => (
              <div key={index} className="flex flex-wrap items-center gap-2 text-[11px]">
                <code className="rounded bg-surface-hover px-1.5 py-0.5 text-ink">{call.tool}</code>
                <span className="text-muted">{JSON.stringify(call.arguments)}</span>
                {call.error ? (
                  <span className="text-red-400">refused: {call.error}</span>
                ) : (
                  <span className="text-muted">→ {call.row_count} row{call.row_count === 1 ? "" : "s"}</span>
                )}
              </div>
            ))}
          </div>

          {rows.length > 0 && (
            <pre className="max-h-72 overflow-auto rounded-md bg-surface-hover p-3 text-[11px] leading-relaxed text-ink/80">
              {JSON.stringify(rows, null, 2)}
            </pre>
          )}

          {response.grounding && (
            <p className="text-[11px] text-muted">
              Checked: {response.grounding.validated.join(", ")}. Not checked:{" "}
              {response.grounding.not_validated.join(", ")} — {response.grounding.not_validated_note}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function ProposalCard({
  proposal,
  onDecided,
}: {
  proposal: Proposal;
  onDecided: (updated: Proposal) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const decide = async (decision: "confirm" | "reject") => {
    setBusy(true);
    setError("");
    try {
      const updated = await api.post<Proposal>(
        `/agent/actions/${proposal.id}/${decision}`,
        decision === "reject" ? { note: "" } : {},
      );
      onDecided(updated);
    } catch (caught) {
      setError(errorMessage(caught, "The action could not be completed."));
    } finally {
      setBusy(false);
    }
  };

  const pending = proposal.status === "proposed";

  return (
    <div className="mt-3 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
      <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-amber-400">
        <AlertTriangle className="h-3.5 w-3.5" />
        Proposed — not carried out
      </div>

      <p className="mt-2 text-sm text-ink">{proposal.effect}</p>
      {proposal.rationale && (
        <p className="mt-1 text-xs italic text-muted">Reason given: {proposal.rationale}</p>
      )}
      <p className="mt-1 text-[11px] text-muted">
        Requires <code className="text-ink/80">{proposal.required_permission}</code> to confirm.
      </p>

      {error && <p className="mt-2 text-xs text-red-400">{error}</p>}

      {pending ? (
        <div className="mt-3 flex gap-2">
          <button
            type="button"
            disabled={busy}
            onClick={() => decide("confirm")}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground disabled:opacity-50"
          >
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
            Confirm
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => decide("reject")}
            className="inline-flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs font-medium text-muted hover:text-ink disabled:opacity-50"
          >
            <X className="h-3.5 w-3.5" />
            Reject
          </button>
        </div>
      ) : (
        <p className="mt-3 text-xs font-medium text-ink">
          {proposal.status === "executed" ? "Confirmed and carried out." : `Status: ${proposal.status}.`}
          {proposal.error && <span className="text-red-400"> {proposal.error}</span>}
        </p>
      )}
    </div>
  );
}

function NotConfiguredPanel({ provider }: { provider: ProviderStatus }) {
  return (
    <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-5">
      <div className="flex items-center gap-2 text-amber-400">
        <AlertTriangle className="h-5 w-5" />
        <h2 className="text-sm font-semibold">The security engineer is not configured</h2>
      </div>

      <p className="mt-3 text-sm text-ink/90">{provider.why_required}</p>

      <div className="mt-4">
        <p className="text-xs font-semibold uppercase tracking-wider text-muted">Missing</p>
        <ul className="mt-1 space-y-0.5">
          {provider.missing.map((name) => (
            <li key={name}>
              <code className="text-xs text-ink">{name}</code>
            </li>
          ))}
        </ul>
      </div>

      <div className="mt-4">
        <p className="text-xs font-semibold uppercase tracking-wider text-muted">How to enable</p>
        <pre className="mt-1 overflow-x-auto rounded-md bg-surface-hover p-3 text-[11px] leading-relaxed text-ink/80">
          {provider.how_to_enable}
        </pre>
      </div>

      <p className="mt-4 text-xs text-muted">
        Implemented in <code>{provider.implemented_in}</code>. Every other page continues to
        read your data directly and is unaffected.
      </p>
    </div>
  );
}

export default function AskAgentPage() {
  const [status, setStatus] = useState<AgentStatus | null>(null);
  const [statusError, setStatusError] = useState("");
  const [turns, setTurns] = useState<Turn[]>([]);
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api
      .get<AgentStatus>("/agent/status")
      .then(setStatus)
      .catch((caught) =>
        setStatusError(
          errorMessage(caught, "Could not read the assistant's status."),
        ),
      );
  }, []);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [turns, loading]);

  const onProposalDecided = useCallback((updated: Proposal) => {
    setTurns((previous) =>
      previous.map((turn) =>
        turn.response
          ? {
              ...turn,
              response: {
                ...turn.response,
                proposals: turn.response.proposals.map((item) =>
                  item.id === updated.id ? updated : item,
                ),
              },
            }
          : turn,
      ),
    );
  }, []);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    const question = input.trim();
    if (!question || loading) return;

    setTurns((previous) => [
      ...previous,
      { id: `u-${previous.length}`, role: "user", content: question },
    ]);
    setInput("");
    setLoading(true);

    try {
      const response = await api.post<AgentResponse>("/agent/chat", {
        message: question,
        conversation_id: conversationId,
      });
      if (response.conversation_id) setConversationId(response.conversation_id);
      setTurns((previous) => [
        ...previous,
        {
          id: response.message_id ?? `a-${previous.length}`,
          role: "assistant",
          content: response.available ? response.answer : response.unavailable_reason,
          response,
        },
      ]);
    } catch (caught) {
      // A transport failure is reported as a transport failure. It is never
      // rendered as though the assistant had answered.
      setTurns((previous) => [
        ...previous,
        {
          id: `e-${previous.length}`,
          role: "assistant",
          content:
            caught instanceof ApiError
              ? `The request failed: ${caught.message}`
              : "The request failed before reaching the assistant.",
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const configured = status?.provider.configured ?? false;

  return (
    <div className="flex h-[calc(100vh-theme(spacing.16))] flex-col space-y-4 p-6">
      <div className="flex flex-shrink-0 items-end justify-between">
        <div>
          <h1 className="flex items-center gap-3 text-3xl font-bold tracking-tight text-ink">
            <BrainCircuit className="h-8 w-8 text-primary" />
            Security Engineer
          </h1>
          <p className="mt-2 text-muted">
            Answers are built from records retrieved out of your database, and checked against them.
          </p>
        </div>

        {status && (
          <div
            className={cn(
              "flex items-center gap-2 rounded-lg border px-4 py-2 text-sm font-semibold",
              configured
                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                : "border-amber-500/30 bg-amber-500/10 text-amber-400",
            )}
          >
            {configured ? <ShieldCheck className="h-5 w-5" /> : <AlertTriangle className="h-5 w-5" />}
            <span>
              {configured
                ? `${status.provider.model} via ${status.provider.provider}`
                : "Not configured"}
            </span>
          </div>
        )}
      </div>

      {statusError && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/5 px-4 py-3 text-sm text-red-400">
          {statusError}
        </div>
      )}

      {status && !configured && <NotConfiguredPanel provider={status.provider} />}

      <div className="flex flex-1 flex-col overflow-hidden rounded-xl border border-border bg-surface shadow-lg">
        <div className="flex-1 space-y-6 overflow-y-auto p-4 sm:p-6">
          {turns.length === 0 && (
            <div className="mx-auto max-w-2xl rounded-lg border border-border bg-surface/60 p-5 text-sm text-muted">
              <div className="mb-2 flex items-center gap-2 text-primary">
                <Sparkles className="h-4 w-4" />
                <span className="text-xs font-semibold uppercase tracking-wider">
                  What this assistant can read
                </span>
              </div>
              {status ? (
                <>
                  <p>
                    It has no knowledge of your environment beyond what these queries return, and
                    it cannot change anything without your explicit confirmation.
                  </p>
                  <ul className="mt-3 grid gap-1 sm:grid-cols-2">
                    {status.retrieval_tools.map((tool) => (
                      <li key={tool.name} className="text-xs">
                        <code className="text-ink/80">{tool.name}</code>
                      </li>
                    ))}
                  </ul>
                </>
              ) : (
                <p>Loading…</p>
              )}
            </div>
          )}

          {turns.map((turn) => (
            <div
              key={turn.id}
              className={cn("flex w-full", turn.role === "user" ? "justify-end" : "justify-start")}
            >
              <div
                className={cn(
                  "flex max-w-[85%] gap-4 md:max-w-[80%]",
                  turn.role === "user" ? "flex-row-reverse" : "flex-row",
                )}
              >
                <div
                  className={cn(
                    "flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-full border",
                    turn.role === "user"
                      ? "border-border bg-surface text-ink"
                      : "border-primary/40 bg-primary/20 text-primary",
                  )}
                >
                  {turn.role === "user" ? <User size={20} /> : <BrainCircuit size={20} />}
                </div>

                <div
                  className={cn(
                    "min-w-0 rounded-2xl border px-5 py-4 text-sm",
                    turn.role === "user"
                      ? "border-border bg-surface-hover text-ink"
                      : "border-primary/20 bg-primary/5 text-ink/90",
                  )}
                >
                  {turn.response?.grounding && (
                    <div className="mb-2">
                      <GroundingBadge status={turn.response.grounding.status} />
                    </div>
                  )}

                  <div className="whitespace-pre-wrap">{turn.content}</div>

                  {turn.response?.grounding?.status === "rejected" &&
                    turn.response.grounding.unsupported_references.length > 0 && (
                      <p className="mt-2 text-xs text-red-400">
                        Could not be traced to a record:{" "}
                        {turn.response.grounding.unsupported_references.join(", ")}
                      </p>
                    )}

                  {turn.response?.proposals.map((proposal) => (
                    <ProposalCard
                      key={proposal.id}
                      proposal={proposal}
                      onDecided={onProposalDecided}
                    />
                  ))}

                  {turn.response && <EvidencePanel response={turn.response} />}
                </div>
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex justify-start">
              <div className="flex max-w-[75%] gap-4">
                <div className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-full border border-primary/40 bg-primary/20 text-primary">
                  <BrainCircuit size={20} />
                </div>
                <div className="flex items-center gap-3 rounded-2xl border border-primary/20 bg-primary/5 px-5 py-4 text-sm">
                  <Loader2 className="h-4 w-4 animate-spin text-primary" />
                  <span className="italic text-muted">Querying your database…</span>
                </div>
              </div>
            </div>
          )}
          <div ref={endRef} />
        </div>

        <div className="border-t border-border bg-surface-hover/50 p-4">
          <form onSubmit={handleSubmit} className="relative mx-auto flex max-w-4xl items-center">
            <input
              type="text"
              value={input}
              onChange={(event) => setInput(event.target.value)}
              disabled={loading || !configured}
              placeholder={
                configured
                  ? "Ask about findings, assets, exposure or remediation…"
                  : "Configure a model to enable the assistant"
              }
              className="h-14 w-full rounded-xl border border-border bg-surface pl-6 pr-16 text-ink shadow-inner placeholder:text-muted focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary disabled:opacity-50"
            />
            <button
              type="submit"
              disabled={!input.trim() || loading || !configured}
              className="absolute right-2 flex h-10 w-10 items-center justify-center rounded-lg bg-primary text-primary-foreground shadow-lg transition-colors hover:bg-primary/90 disabled:opacity-50"
            >
              <Send className="h-4 w-4" />
            </button>
          </form>
          <p className="mt-3 text-center text-[10px] text-muted">
            Identifiers in every answer are checked against the records retrieved. Counts and
            interpretations are not — open the evidence panel to compare.
          </p>
        </div>
      </div>
    </div>
  );
}
