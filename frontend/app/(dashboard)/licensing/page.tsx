"use client";

import { useEffect, useState } from "react";
import { useAuthStore } from "@/store/auth";
import { BadgeDollarSign, Users, CreditCard, ShieldCheck, ArrowUpRight } from "lucide-react";
import { cn } from "@/lib/utils";

export default function LicensingPage() {
  const token = useAuthStore((s) => s.accessToken);
  const [org, setOrg] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("http://localhost:8000/api/v1/organizations/current", {
      headers: { Authorization: `Bearer ${token}` }
    })
      .then(res => res.json())
      .then(data => {
        setOrg(data);
        setLoading(false);
      });
  }, [token]);

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
      </div>
    );
  }

  const usagePercent = Math.min((3 / (org.license_seats || 10)) * 100, 100);

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-ink">Licensing & Billing</h1>
        <p className="text-sm text-muted">Manage your subscription and monitor seat usage.</p>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <div className="rounded-xl border border-border bg-gradient-to-br from-surface to-surface-hover p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="rounded-full bg-primary/10 p-3">
              <BadgeDollarSign className="h-6 w-6 text-primary" />
            </div>
            <span className="rounded-full border border-primary/20 bg-primary/10 px-3 py-1 text-xs font-semibold uppercase tracking-wider text-primary">
              {org.subscription_plan}
            </span>
          </div>
          <h2 className="text-3xl font-bold text-ink mb-1">Active Subscription</h2>
          <p className="text-sm text-muted mb-6">Your plan renews automatically on Jan 1, 2027.</p>
          
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <ShieldCheck className="h-5 w-5 text-green-500" />
              <span className="text-sm text-ink/80">Premium Support</span>
            </div>
            <div className="flex items-center gap-3">
              <ShieldCheck className="h-5 w-5 text-green-500" />
              <span className="text-sm text-ink/80">Unlimited Asset Scans</span>
            </div>
            <div className="flex items-center gap-3">
              <ShieldCheck className="h-5 w-5 text-green-500" />
              <span className="text-sm text-ink/80">Threat Intelligence Feed</span>
            </div>
          </div>

          <button className="mt-8 flex w-full items-center justify-center gap-2 rounded-lg bg-ink px-4 py-2.5 text-sm font-medium text-surface transition-colors hover:bg-ink/90">
            Upgrade Plan <ArrowUpRight className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-6">
          <div className="rounded-xl border border-border bg-surface p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold text-ink flex items-center gap-2">
                <Users className="h-5 w-5 text-muted" /> User Seats
              </h3>
              <span className="text-sm font-medium text-ink">3 / {org.license_seats}</span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-full bg-surface-hover">
              <div 
                className="h-full bg-primary transition-all duration-500"
                style={{ width: `${usagePercent}%` }}
              />
            </div>
            <p className="mt-3 text-xs text-muted">
              You have {org.license_seats - 3} seats remaining on your current license.
            </p>
          </div>

          <div className="rounded-xl border border-border bg-surface p-6">
            <h3 className="font-semibold text-ink flex items-center gap-2 mb-4">
              <CreditCard className="h-5 w-5 text-muted" /> Payment Method
            </h3>
            <div className="flex items-center justify-between rounded-lg border border-border bg-surface-hover/50 p-4">
              <div className="flex items-center gap-3">
                <div className="h-8 w-12 rounded bg-ink/10 flex items-center justify-center font-bold text-[10px] text-ink">
                  VISA
                </div>
                <div>
                  <p className="text-sm font-medium text-ink">•••• •••• •••• 4242</p>
                  <p className="text-xs text-muted">Expires 12/28</p>
                </div>
              </div>
              <button className="text-sm font-medium text-primary hover:underline">
                Update
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
