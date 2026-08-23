"use client";

import { useEffect, useMemo, useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import {
  AlertTriangle, ChevronLeft, ChevronRight, Download, FileClock, Loader2,
  Search, X,
} from "lucide-react";
import { api, ApiError } from "@/lib/api";

/**
 * Audit log.
 *
 * The search box previously set state that nothing read, the "Filter" and
 * "Export Logs" buttons had no handlers at all, and the fetch ran once on mount
 * with no parameters — so the page showed the fifty most recent entries and
 * offered three controls that did nothing.
 *
 * Every filter here is sent to the server, the export applies the same filters
 * the screen is showing, and the pagination uses the `total` the response has
 * always carried.
 */

const PAGE_SIZE = 50;
const SEARCH_DEBOUNCE_MS = 300;

interface AuditEntry {
  id: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  ip_address: string | null;
  created_at: string | null;
  actor_user_id: string | null;
  actor_email: string | null;
  actor_name: string | null;
  actor_note: string;
  metadata: Record<string, unknown>;
}

interface AuditResponse {
  items: AuditEntry[];
  total: number;
  skip: number;
  limit: number;
}

interface FilterOptions {
  actions: string[];
  resource_types: string[];
  actors: { id: string; email: string; full_name: string }[];
}

interface Filters {
  search: string;
  action: string;
  resource_type: string;
  actor_user_id: string;
  date_from: string;
  date_to: string;
}

const EMPTY_FILTERS: Filters = {
  search: "",
  action: "",
  resource_type: "",
  actor_user_id: "",
  date_from: "",
  date_to: "",
};

function toQuery(filters: Filters, skip: number): string {
  const params = new URLSearchParams();
  params.set("skip", String(skip));
  params.set("limit", String(PAGE_SIZE));
  for (const [key, value] of Object.entries(filters)) {
    if (value) params.set(key, value);
  }
  return params.toString();
}

function exportQuery(filters: Filters): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (value) params.set(key, value);
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}

export default function AuditLogsPage() {
  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS);
  const [searchInput, setSearchInput] = useState("");
  const [skip, setSkip] = useState(0);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState("");

  // Debounced so typing does not fire a request per keystroke.
  useEffect(() => {
    const timer = setTimeout(() => {
      setFilters((previous) => ({ ...previous, search: searchInput }));
      setSkip(0);
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [searchInput]);

  const { data, isLoading, isFetching, error } = useQuery<AuditResponse>({
    queryKey: ["audit-logs", filters, skip],
    queryFn: () => api.get<AuditResponse>(`/audit-logs?${toQuery(filters, skip)}`),
    placeholderData: keepPreviousData,
  });

  const { data: options } = useQuery<FilterOptions>({
    queryKey: ["audit-logs", "filters"],
    queryFn: () => api.get<FilterOptions>("/audit-logs/filters"),
  });

  const setFilter = (key: keyof Filters, value: string) => {
    setFilters((previous) => ({ ...previous, [key]: value }));
    setSkip(0);
  };

  const activeFilterCount = useMemo(
    () => Object.values(filters).filter(Boolean).length,
    [filters],
  );

  const runExport = async () => {
    setExporting(true);
    setExportError("");
    const stamp = new Date().toISOString().slice(0, 10);
    try {
      await api.download(
        `/audit-logs/export.pdf${exportQuery(filters)}`,
        `audit-log-${stamp}.pdf`,
      );
    } catch (caught) {
      setExportError(
        caught instanceof ApiError ? caught.message : "The export did not complete.",
      );
    } finally {
      setExporting(false);
    }
  };

  const entries = data?.items ?? [];
  const total = data?.total ?? 0;
  const page = Math.floor(skip / PAGE_SIZE) + 1;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="space-y-6 p-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-3 text-3xl font-bold tracking-tight text-ink">
            <FileClock className="h-8 w-8 text-primary" />
            Audit Log
          </h1>
          <p className="mt-2 text-muted">
            Every recorded action in this organization, with who performed it and
            from where.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {exportError && (
            <span className="text-xs text-red-400">{exportError}</span>
          )}
          <button
            type="button"
            onClick={runExport}
            disabled={exporting}
            className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground disabled:opacity-50"
          >
            {exporting ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Download className="h-4 w-4" />
            )}
            Export PDF
            {activeFilterCount > 0 && (
              <span className="rounded bg-black/20 px-1.5 py-0.5 text-[10px]">
                filtered
              </span>
            )}
          </button>
        </div>
      </div>

      <section className="rounded-xl border border-border bg-surface p-4">
        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-6">
          <div className="lg:col-span-2">
            <label className="mb-1 block text-[11px] font-medium text-muted">
              Search
            </label>
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
              <input
                value={searchInput}
                onChange={(event) => setSearchInput(event.target.value)}
                placeholder="Name, email, action, resource, IP…"
                className="h-9 w-full rounded-lg border border-border bg-background pl-9 pr-8 text-sm text-ink placeholder:text-muted focus:border-primary focus:outline-none"
              />
              {searchInput && (
                <button
                  type="button"
                  onClick={() => setSearchInput("")}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-muted hover:text-ink"
                  aria-label="Clear search"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
            </div>
          </div>

          <div>
            <label className="mb-1 block text-[11px] font-medium text-muted">Actor</label>
            <select
              value={filters.actor_user_id}
              onChange={(event) => setFilter("actor_user_id", event.target.value)}
              className="h-9 w-full rounded-lg border border-border bg-background px-2 text-sm text-ink focus:border-primary focus:outline-none"
            >
              <option value="">Anyone</option>
              {options?.actors.map((actor) => (
                <option key={actor.id} value={actor.id}>
                  {actor.full_name || actor.email}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="mb-1 block text-[11px] font-medium text-muted">Action</label>
            <select
              value={filters.action}
              onChange={(event) => setFilter("action", event.target.value)}
              className="h-9 w-full rounded-lg border border-border bg-background px-2 text-sm text-ink focus:border-primary focus:outline-none"
            >
              <option value="">Any action</option>
              {/* Derived from the data, so this can never offer a value that
                  returns nothing, nor omit an action a new feature records. */}
              {options?.actions.map((action) => (
                <option key={action} value={action}>
                  {action.replace(/_/g, " ")}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="mb-1 block text-[11px] font-medium text-muted">
              Resource
            </label>
            <select
              value={filters.resource_type}
              onChange={(event) => setFilter("resource_type", event.target.value)}
              className="h-9 w-full rounded-lg border border-border bg-background px-2 text-sm text-ink focus:border-primary focus:outline-none"
            >
              <option value="">Any resource</option>
              {options?.resource_types.map((type) => (
                <option key={type} value={type}>
                  {type.replace(/_/g, " ")}
                </option>
              ))}
            </select>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="mb-1 block text-[11px] font-medium text-muted">From</label>
              <input
                type="date"
                value={filters.date_from}
                onChange={(event) => setFilter("date_from", event.target.value)}
                className="h-9 w-full rounded-lg border border-border bg-background px-2 text-xs text-ink focus:border-primary focus:outline-none"
              />
            </div>
            <div>
              <label className="mb-1 block text-[11px] font-medium text-muted">To</label>
              <input
                type="date"
                value={filters.date_to}
                onChange={(event) => setFilter("date_to", event.target.value)}
                className="h-9 w-full rounded-lg border border-border bg-background px-2 text-xs text-ink focus:border-primary focus:outline-none"
              />
            </div>
          </div>
        </div>

        {activeFilterCount > 0 && (
          <button
            type="button"
            onClick={() => {
              setFilters(EMPTY_FILTERS);
              setSearchInput("");
              setSkip(0);
            }}
            className="mt-3 text-xs font-medium text-primary hover:underline"
          >
            Clear {activeFilterCount} filter{activeFilterCount === 1 ? "" : "s"}
          </button>
        )}
      </section>

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-400">
          <AlertTriangle className="h-5 w-5" />
          {error instanceof ApiError ? error.message : "The audit log could not be loaded."}
        </div>
      )}

      <section className="rounded-xl border border-border bg-surface">
        <div className="flex items-center justify-between border-b border-border px-5 py-3">
          <p className="text-xs text-muted">
            {total.toLocaleString()} entr{total === 1 ? "y" : "ies"}
            {activeFilterCount > 0 && " matching these filters"}
          </p>
          {isFetching && !isLoading && (
            <Loader2 className="h-3.5 w-3.5 animate-spin text-muted" />
          )}
        </div>

        {isLoading ? (
          <div className="flex h-40 items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin text-muted" />
          </div>
        ) : entries.length === 0 ? (
          <div className="p-8 text-center text-sm text-muted">
            No entries match these filters. That reflects what the log holds; it
            is not an assertion that nothing happened.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs uppercase tracking-wider text-muted">
                  <th className="px-5 py-3 font-medium">When</th>
                  <th className="px-5 py-3 font-medium">Actor</th>
                  <th className="px-5 py-3 font-medium">Action</th>
                  <th className="px-5 py-3 font-medium">Resource</th>
                  <th className="px-5 py-3 font-medium">Source IP</th>
                  <th className="px-5 py-3 font-medium">Detail</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => (
                  <tr
                    key={entry.id}
                    className="border-b border-border/60 align-top last:border-0 hover:bg-surface-hover"
                  >
                    <td className="whitespace-nowrap px-5 py-3 text-xs text-muted">
                      {entry.created_at
                        ? new Date(entry.created_at).toLocaleString()
                        : "—"}
                    </td>
                    <td className="px-5 py-3">
                      {entry.actor_email ? (
                        <>
                          <div className="text-ink">
                            {entry.actor_name || entry.actor_email}
                          </div>
                          {entry.actor_name && (
                            <div className="text-[11px] text-muted">
                              {entry.actor_email}
                            </div>
                          )}
                        </>
                      ) : (
                        <span
                          className="cursor-help border-b border-dotted border-muted/50 text-xs text-muted"
                          title={entry.actor_note}
                        >
                          System
                        </span>
                      )}
                    </td>
                    <td className="px-5 py-3">
                      <code className="rounded bg-surface-hover px-1.5 py-0.5 text-[11px] text-ink">
                        {entry.action}
                      </code>
                    </td>
                    <td className="px-5 py-3 text-xs text-muted">
                      {entry.resource_type}
                      {entry.resource_id && (
                        <div className="text-[10px] opacity-70">{entry.resource_id}</div>
                      )}
                    </td>
                    <td className="px-5 py-3 text-xs text-muted">
                      {entry.ip_address || "—"}
                    </td>
                    <td className="max-w-xs px-5 py-3 text-[11px] text-muted">
                      {Object.keys(entry.metadata || {}).length > 0
                        ? Object.entries(entry.metadata)
                            .slice(0, 4)
                            .map(([key, value]) => `${key}=${String(value)}`)
                            .join(" · ")
                        : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {pages > 1 && (
          <div className="flex items-center justify-between border-t border-border px-5 py-3">
            <p className="text-xs text-muted">
              Page {page} of {pages}
            </p>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setSkip(Math.max(0, skip - PAGE_SIZE))}
                disabled={skip === 0}
                className="inline-flex items-center gap-1 rounded-lg border border-border px-3 py-1.5 text-xs text-ink hover:bg-surface-hover disabled:opacity-40"
              >
                <ChevronLeft className="h-3.5 w-3.5" />
                Previous
              </button>
              <button
                type="button"
                onClick={() => setSkip(skip + PAGE_SIZE)}
                disabled={page >= pages}
                className="inline-flex items-center gap-1 rounded-lg border border-border px-3 py-1.5 text-xs text-ink hover:bg-surface-hover disabled:opacity-40"
              >
                Next
                <ChevronRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
