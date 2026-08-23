"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, KeyRound, Loader2, ShieldCheck, ShieldX, Users } from "lucide-react";
import { api, ApiError, errorMessage } from "@/lib/api";
import {
  IntegrationPanel, IntegrationState,
} from "@/components/integrations/integration-panel";

/**
 * Directory accounts.
 *
 * MFA has three states here, not two. Null means the directory's user listing
 * does not report factor enrolment — which is what Okta's `/api/v1/users` and
 * Microsoft Graph's `/v1.0/users` actually return. The previous schema
 * defaulted the column to `false`, so an account whose status was simply
 * unknown was displayed as having MFA disabled: a security claim nobody made,
 * and exactly the kind someone acts on.
 */

interface Identity {
  id: string;
  email: string;
  full_name: string;
  provider: string;
  is_active: boolean;
  mfa_enabled: boolean | null;
  mfa_note: string;
  last_login: string | null;
  privilege_level: string | null;
  last_seen: string | null;
}

interface IdentityResponse {
  identities: Identity[];
  integrations: IntegrationState[];
  summary: {
    total: number;
    inactive: number;
    mfa_enabled: number;
    mfa_disabled: number;
    mfa_unknown: number;
  };
  summary_note: string;
  empty_state_note: string;
}

function MfaCell({ identity }: { identity: Identity }) {
  if (identity.mfa_enabled === true) {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs text-emerald-400">
        <ShieldCheck className="h-3.5 w-3.5" />
        Enrolled
      </span>
    );
  }
  if (identity.mfa_enabled === false) {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs text-red-400">
        <ShieldX className="h-3.5 w-3.5" />
        Not enrolled
      </span>
    );
  }
  return (
    <span
      className="cursor-help border-b border-dotted border-muted/50 text-xs text-muted"
      title={identity.mfa_note}
    >
      Unknown
    </span>
  );
}

export default function IdentityPage() {
  const queryClient = useQueryClient();

  const { data, isLoading, error } = useQuery<IdentityResponse>({
    queryKey: ["identity"],
    queryFn: () => api.get<IdentityResponse>("/identity/"),
  });

  const runDiscovery = async (provider: string) => {
    await api.post("/identity/scan", { provider });
    await queryClient.invalidateQueries({ queryKey: ["identity"] });
  };

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-muted" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-400">
          <AlertTriangle className="h-5 w-5" />
          {errorMessage(error, "Identities could not be loaded.")}
        </div>
      </div>
    );
  }

  const identities = data?.identities ?? [];
  const summary = data?.summary;

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="flex items-center gap-3 text-3xl font-bold tracking-tight text-ink">
          <KeyRound className="h-8 w-8 text-primary" />
          Identity
        </h1>
        <p className="mt-2 text-muted">
          Accounts read from your directory. Nothing is inferred — a field the
          directory does not return is shown as unknown.
        </p>
      </div>

      <section>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-muted">
          Integrations
        </h2>
        <IntegrationPanel
          integrations={data?.integrations ?? []}
          onRun={runDiscovery}
          runLabel="Read accounts"
        />
      </section>

      {summary && (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
            {[
              { label: "Accounts", value: summary.total, icon: Users },
              { label: "Disabled", value: summary.inactive, icon: ShieldX },
              { label: "MFA enrolled", value: summary.mfa_enabled, icon: ShieldCheck },
              { label: "MFA not enrolled", value: summary.mfa_disabled, icon: ShieldX },
              { label: "MFA unknown", value: summary.mfa_unknown, icon: AlertTriangle },
            ].map(({ label, value, icon: Icon }) => (
              <div key={label} className="rounded-xl border border-border bg-surface p-5">
                <div className="flex items-center justify-between">
                  <p className="text-xs font-medium uppercase tracking-wider text-muted">
                    {label}
                  </p>
                  <Icon className="h-4 w-4 text-muted" />
                </div>
                <p className="mt-2 text-2xl font-bold text-ink">{value}</p>
              </div>
            ))}
          </div>

          {data?.summary_note && (
            <p className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-4 py-3 text-xs text-amber-400">
              {data.summary_note}
            </p>
          )}
        </>
      )}

      <section className="rounded-xl border border-border bg-surface">
        <div className="border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold text-ink">Accounts</h2>
        </div>

        {identities.length === 0 ? (
          <div className="p-8 text-center text-sm text-muted">
            {data?.empty_state_note || "No accounts have been read."}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs uppercase tracking-wider text-muted">
                  <th className="px-5 py-3 font-medium">Account</th>
                  <th className="px-5 py-3 font-medium">Provider</th>
                  <th className="px-5 py-3 font-medium">State</th>
                  <th className="px-5 py-3 font-medium">MFA</th>
                  <th className="px-5 py-3 font-medium">Privilege</th>
                  <th className="px-5 py-3 font-medium">Last login</th>
                </tr>
              </thead>
              <tbody>
                {identities.map((identity) => (
                  <tr
                    key={identity.id}
                    className="border-b border-border/60 last:border-0 hover:bg-surface-hover"
                  >
                    <td className="px-5 py-3">
                      <div className="font-medium text-ink">
                        {identity.full_name || identity.email}
                      </div>
                      {identity.full_name && (
                        <div className="text-[11px] text-muted">{identity.email}</div>
                      )}
                    </td>
                    <td className="px-5 py-3 text-muted">{identity.provider}</td>
                    <td className="px-5 py-3">
                      <span
                        className={
                          identity.is_active ? "text-xs text-emerald-400" : "text-xs text-muted"
                        }
                      >
                        {identity.is_active ? "Active" : "Disabled"}
                      </span>
                    </td>
                    <td className="px-5 py-3">
                      <MfaCell identity={identity} />
                    </td>
                    <td className="px-5 py-3 text-muted">
                      {identity.privilege_level || (
                        <span className="text-xs">Not reported</span>
                      )}
                    </td>
                    <td className="px-5 py-3 text-muted">
                      {identity.last_login
                        ? new Date(identity.last_login).toLocaleDateString()
                        : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
