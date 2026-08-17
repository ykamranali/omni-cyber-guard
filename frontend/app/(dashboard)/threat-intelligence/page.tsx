"use client";

import { useEffect, useState } from "react";
import { useAuthStore } from "@/store/auth";
import { Satellite, ShieldAlert, Activity, Search, Shield, AlertTriangle } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { cn } from "@/lib/utils";

interface ThreatAdvisory {
  id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  cvss: number;
  description: string;
  published_at: string;
  tags: string[];
}

interface ThreatIntel {
  global_risk_level: string;
  active_campaigns: number;
  zero_days_tracked: number;
  latest_advisories: ThreatAdvisory[];
}

export default function ThreatIntelligencePage() {
  const [data, setData] = useState<ThreatIntel | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const token = useAuthStore((s) => s.accessToken);

  useEffect(() => {
    fetch("http://localhost:8000/api/v1/threat-intel", {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.json())
      .then((data) => {
        setData(data);
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

  const filteredAdvisories = data?.latest_advisories.filter((a) =>
    a.title.toLowerCase().includes(search.toLowerCase()) ||
    a.id.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-ink">Threat Intelligence</h1>
        <p className="text-sm text-muted">Real-time global vulnerability advisories and threat tracking.</p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <div className="rounded-xl border border-border bg-surface p-5">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-red-500/10 p-2">
              <Activity className="h-5 w-5 text-red-500" />
            </div>
            <div>
              <p className="text-sm font-medium text-muted">Global Risk Level</p>
              <h2 className="text-2xl font-bold text-ink">{data?.global_risk_level}</h2>
            </div>
          </div>
        </div>
        <div className="rounded-xl border border-border bg-surface p-5">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-primary/10 p-2">
              <ShieldAlert className="h-5 w-5 text-primary" />
            </div>
            <div>
              <p className="text-sm font-medium text-muted">Active Campaigns</p>
              <h2 className="text-2xl font-bold text-ink">{data?.active_campaigns}</h2>
            </div>
          </div>
        </div>
        <div className="rounded-xl border border-border bg-surface p-5">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-purple-500/10 p-2">
              <Satellite className="h-5 w-5 text-purple-500" />
            </div>
            <div>
              <p className="text-sm font-medium text-muted">Zero-Days Tracked</p>
              <h2 className="text-2xl font-bold text-ink">{data?.zero_days_tracked}</h2>
            </div>
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-border bg-surface">
        <div className="border-b border-border p-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-ink">Latest Advisories</h2>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
              <input
                type="text"
                placeholder="Search advisories..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-64 rounded-lg border border-border bg-surface-hover pl-9 pr-4 py-2 text-sm text-ink placeholder:text-muted focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
          </div>
        </div>
        <div className="divide-y divide-border">
          {filteredAdvisories?.map((advisory) => (
            <div key={advisory.id} className="flex gap-4 p-5 hover:bg-surface-hover/50 transition-colors">
              <div className="mt-1 flex-shrink-0">
                {advisory.severity === "CRITICAL" ? (
                  <AlertTriangle className="h-6 w-6 text-red-500" />
                ) : (
                  <Shield className="h-6 w-6 text-orange-500" />
                )}
              </div>
              <div className="flex-1 space-y-2">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="font-semibold text-ink">{advisory.title}</h3>
                    <div className="mt-1 flex items-center gap-3 text-xs text-muted">
                      <span className="font-mono text-primary">{advisory.id}</span>
                      <span>•</span>
                      <span>Published {formatDistanceToNow(new Date(advisory.published_at), { addSuffix: true })}</span>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className={cn(
                      "inline-flex rounded-full px-2 py-0.5 text-xs font-semibold",
                      advisory.severity === "CRITICAL" ? "bg-red-500/10 text-red-500" :
                      advisory.severity === "HIGH" ? "bg-orange-500/10 text-orange-500" :
                      "bg-yellow-500/10 text-yellow-500"
                    )}>
                      CVSS {advisory.cvss.toFixed(1)}
                    </span>
                  </div>
                </div>
                <p className="text-sm text-ink/80">{advisory.description}</p>
                <div className="flex gap-2 pt-1">
                  {advisory.tags.map((tag) => (
                    <span key={tag} className="rounded border border-border bg-surface-hover px-2 py-0.5 text-[10px] font-medium text-muted">
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}
          {filteredAdvisories?.length === 0 && (
            <div className="p-8 text-center text-muted">No advisories match your search.</div>
          )}
        </div>
      </div>
    </div>
  );
}
