"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle, BadgeCheck, Building2, Check, Loader2, Mail,
  MessageCircle, Pencil, Phone, ScrollText, Users, X,
} from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { useAuthStore } from "@/store/auth";
import { cn } from "@/lib/utils";

/**
 * Licensing.
 *
 * This page was entirely fabricated: a hardcoded plan called "Omni One", a
 * renewal date of "Dec 31, 2028", an org named "Acme Corp Global", a tenant id
 * `org_7f8a9b2c1d3e4f5`, an allocation of 8,492 of 10,000 assets, and a
 * progress bar with `style={{ width: "85%" }}`. None of it came from anywhere,
 * and the real values were sitting unused on `/organizations/current` —
 * `subscription_plan`, `license_seats`, `name`.
 *
 * Seat usage is now the actual count of active users against the actual seat
 * limit, and the plan and organization name are read, not invented.
 */

const SALES_EMAIL = "ykamranali7777@gmail.com";
const SALES_PHONE = "+971508169288";
// WhatsApp's click-to-chat expects the number without punctuation.
const SALES_WHATSAPP = SALES_PHONE.replace(/[^0-9]/g, "");

interface Organization {
  id: string;
  name: string;
  slug: string;
  subscription_plan: string;
  license_seats: number;
  is_active: boolean;
  created_at?: string;
}

interface UserRecord {
  id: string;
  is_active: boolean;
}

function SeatMeter({ used, total }: { used: number; total: number }) {
  const safeTotal = Math.max(total, 0);
  const percent = safeTotal > 0 ? Math.min(100, (used / safeTotal) * 100) : 0;
  const tone =
    percent >= 95 ? "bg-critical" : percent >= 80 ? "bg-high" : "bg-primary";

  return (
    <div>
      <div className="flex items-baseline justify-between">
        <p className="text-2xl font-bold text-ink">
          {used}
          <span className="text-base font-normal text-muted"> / {safeTotal || "—"}</span>
        </p>
        {safeTotal > 0 && (
          <p className="text-xs text-muted">{percent.toFixed(0)}% used</p>
        )}
      </div>
      <div className="mt-3 h-2 overflow-hidden rounded-full bg-surface-hover">
        {/* Width comes from the real ratio. It was a literal 85% before. */}
        <div
          className={cn("h-full rounded-full transition-all", tone)}
          style={{ width: `${percent}%` }}
        />
      </div>
      {safeTotal > 0 && used > safeTotal && (
        <p className="mt-2 text-xs text-critical">
          {used - safeTotal} account(s) over the licensed limit.
        </p>
      )}
    </div>
  );
}

export default function LicensingPage() {
  const queryClient = useQueryClient();
  const currentUser = useAuthStore((state) => state.user);
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState({ subscription_plan: "", license_seats: 0 });
  const [saveError, setSaveError] = useState("");

  const { data: organization, isLoading, error } = useQuery<Organization>({
    queryKey: ["organizations", "current"],
    queryFn: () => api.get<Organization>("/organizations/current"),
  });

  const { data: users } = useQuery<UserRecord[]>({
    queryKey: ["users"],
    queryFn: () => api.get<UserRecord[]>("/users"),
    retry: false,
  });

  const save = useMutation({
    // Plan and seats are a platform-level change, restricted to super
    // administrators — an organization administrator raising their own seat
    // limit is a billing decision, not a setting.
    mutationFn: () =>
      api.patch(`/organizations/${organization!.id}/license`, {
        subscription_plan: form.subscription_plan,
        license_seats: Number(form.license_seats),
      }),
    onSuccess: () => {
      setEditing(false);
      setSaveError("");
      void queryClient.invalidateQueries({ queryKey: ["organizations"] });
    },
    onError: (caught) =>
      setSaveError(
        caught instanceof ApiError ? caught.message : "The change could not be saved.",
      ),
  });

  const startEditing = () => {
    if (!organization) return;
    setForm({
      subscription_plan: organization.subscription_plan,
      license_seats: organization.license_seats,
    });
    setSaveError("");
    setEditing(true);
  };

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-muted" />
      </div>
    );
  }

  if (error || !organization) {
    return (
      <div className="p-6">
        <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-400">
          <AlertTriangle className="h-5 w-5" />
          {error instanceof ApiError
            ? error.message
            : "Licensing information could not be loaded."}
        </div>
      </div>
    );
  }

  const activeUsers = users?.filter((user) => user.is_active).length ?? 0;
  const canManage = Boolean(currentUser?.is_super_admin);

  return (
    <div className="space-y-6 p-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-3 text-3xl font-bold tracking-tight text-ink">
            <ScrollText className="h-8 w-8 text-primary" />
            Licensing
          </h1>
          <p className="mt-2 text-muted">
            Your subscription and seat usage, read from this organization&apos;s
            record.
          </p>
        </div>

        {canManage && !editing && (
          <button
            type="button"
            onClick={startEditing}
            className="inline-flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm font-medium text-ink hover:bg-surface-hover"
          >
            <Pencil className="h-4 w-4" />
            Edit licence
          </button>
        )}
      </div>

      <div className="grid gap-5 lg:grid-cols-3">
        <div className="rounded-xl border border-border bg-surface p-6">
          <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-muted">
            <BadgeCheck className="h-4 w-4" />
            Plan
          </div>

          {editing ? (
            <div className="mt-4 space-y-3">
              <div>
                <label className="mb-1 block text-[11px] text-muted">Plan name</label>
                <input
                  value={form.subscription_plan}
                  onChange={(event) =>
                    setForm((previous) => ({
                      ...previous,
                      subscription_plan: event.target.value,
                    }))
                  }
                  className="h-9 w-full rounded-lg border border-border bg-background px-3 text-sm text-ink focus:border-primary focus:outline-none"
                />
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-muted">Licensed seats</label>
                <input
                  type="number"
                  min={0}
                  value={form.license_seats}
                  onChange={(event) =>
                    setForm((previous) => ({
                      ...previous,
                      license_seats: Number(event.target.value),
                    }))
                  }
                  className="h-9 w-full rounded-lg border border-border bg-background px-3 text-sm text-ink focus:border-primary focus:outline-none"
                />
              </div>

              {saveError && <p className="text-xs text-red-400">{saveError}</p>}

              <div className="flex gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => save.mutate()}
                  disabled={save.isPending}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground disabled:opacity-50"
                >
                  {save.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Check className="h-3.5 w-3.5" />
                  )}
                  Save
                </button>
                <button
                  type="button"
                  onClick={() => setEditing(false)}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs text-muted hover:text-ink"
                >
                  <X className="h-3.5 w-3.5" />
                  Cancel
                </button>
              </div>
            </div>
          ) : (
            <>
              <p className="mt-3 text-2xl font-bold capitalize text-ink">
                {organization.subscription_plan || "Not set"}
              </p>
              <p className="mt-2 text-xs text-muted">
                {organization.is_active
                  ? "This organization is active."
                  : "This organization is deactivated."}
              </p>
            </>
          )}
        </div>

        <div className="rounded-xl border border-border bg-surface p-6">
          <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-muted">
            <Users className="h-4 w-4" />
            Seats in use
          </div>
          <div className="mt-3">
            <SeatMeter used={activeUsers} total={organization.license_seats} />
          </div>
          <p className="mt-3 text-xs text-muted">
            Counted from active user accounts in this organization.
          </p>
        </div>

        <div className="rounded-xl border border-border bg-surface p-6">
          <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-muted">
            <Building2 className="h-4 w-4" />
            Organization
          </div>
          <p className="mt-3 truncate text-lg font-semibold text-ink" title={organization.name}>
            {organization.name}
          </p>
          <dl className="mt-3 space-y-1.5 text-xs">
            <div className="flex justify-between gap-3">
              <dt className="text-muted">Identifier</dt>
              <dd className="truncate font-mono text-ink/80" title={organization.slug}>
                {organization.slug}
              </dd>
            </div>
            {organization.created_at && (
              <div className="flex justify-between gap-3">
                <dt className="text-muted">Created</dt>
                <dd className="text-ink/80">
                  {new Date(organization.created_at).toLocaleDateString()}
                </dd>
              </div>
            )}
          </dl>
        </div>
      </div>

      <section className="rounded-xl border border-border bg-surface p-6">
        <h2 className="text-sm font-semibold text-ink">Talk to sales</h2>
        <p className="mt-1 text-sm text-muted">
          To change your plan, add seats or discuss a deployment, get in touch
          directly.
        </p>

        <div className="mt-5 grid gap-3 sm:grid-cols-3">
          <a
            href={`mailto:${SALES_EMAIL}?subject=${encodeURIComponent(
              `Omni Cyber Guard — licensing enquiry (${organization.name})`,
            )}`}
            className="flex items-center gap-3 rounded-lg border border-border bg-background p-4 transition-colors hover:border-primary/40 hover:bg-surface-hover"
          >
            <Mail className="h-5 w-5 shrink-0 text-primary" />
            <div className="min-w-0">
              <p className="text-xs font-medium text-ink">Email</p>
              <p className="truncate text-[11px] text-muted">{SALES_EMAIL}</p>
            </div>
          </a>

          <a
            href={`https://wa.me/${SALES_WHATSAPP}?text=${encodeURIComponent(
              `Hello — I'd like to talk about Omni Cyber Guard licensing for ${organization.name}.`,
            )}`}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-3 rounded-lg border border-border bg-background p-4 transition-colors hover:border-primary/40 hover:bg-surface-hover"
          >
            <MessageCircle className="h-5 w-5 shrink-0 text-emerald-400" />
            <div className="min-w-0">
              <p className="text-xs font-medium text-ink">WhatsApp</p>
              <p className="truncate text-[11px] text-muted">{SALES_PHONE}</p>
            </div>
          </a>

          <a
            href={`tel:${SALES_PHONE}`}
            className="flex items-center gap-3 rounded-lg border border-border bg-background p-4 transition-colors hover:border-primary/40 hover:bg-surface-hover"
          >
            <Phone className="h-5 w-5 shrink-0 text-sky-400" />
            <div className="min-w-0">
              <p className="text-xs font-medium text-ink">Call</p>
              <p className="truncate text-[11px] text-muted">{SALES_PHONE}</p>
            </div>
          </a>
        </div>
      </section>
    </div>
  );
}
