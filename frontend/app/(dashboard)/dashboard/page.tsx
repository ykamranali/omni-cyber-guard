"use client";

import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { HolographicShield } from "@/components/ui/holographic-shield";
import {
  AlertTriangle, ShieldCheck, Server, TrendingUp, ChevronRight, Activity
} from "lucide-react";

import { Topbar } from "@/components/layout/topbar";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScoreRing } from "@/components/dashboard/score-ring";
import { SeverityDonut } from "@/components/dashboard/severity-donut";
import { HeroOrb } from "@/components/dashboard/hero-orb";
import { GeoAssetMap } from "@/components/dashboard/geo-asset-map";
import { RecentScans } from "@/components/dashboard/recent-scans";
import { RiskTrendChart } from "@/components/dashboard/risk-trend-chart";
import { ComplianceRings } from "@/components/dashboard/compliance-rings";
import { SystemStatusWidget } from "@/components/dashboard/system-status";
import { ActivityTicker } from "@/components/dashboard/activity-ticker";
import { api } from "@/lib/api";
import { useAuthStore } from "@/store/auth";

interface DashboardSummary {
  security_score: number;
  risk_score: number;
  findings_by_severity: { critical: number; high: number; medium: number; low: number; info: number };
  total_assets: number;
  active_assets: number;
  asset_health_percent: number;
  compliance_status: Record<string, number>;
  remediation_progress_percent: number;
  open_findings: number;
  remediated_findings_last_30_days: number;
}
interface TrendPoint { date: string; security_score: number; risk_score: number; open_findings: number }
interface AssetOut { id: string; hostname: string; risk_score: number; asset_type: string; site: string | null; latitude: number | null; longitude: number | null }
interface ScanJobOut { id: string; target_cidr: string; status: string; hosts_discovered: number; findings_generated: number; created_at: string }
interface ComponentStatus { name: string; status: string; detail: string }
interface SystemStatusOut { overall_status: string; components: ComponentStatus[] }

export default function DashboardPage() {
  const user = useAuthStore((s) => s.user);
  const [networkInfo, setNetworkInfo] = useState({ local: "Detecting...", public: "Establishing connection..." });

  useEffect(() => {
    fetch("https://api.ipify.org?format=json")
      .then(res => res.json())
      .then(data => setNetworkInfo(prev => ({ ...prev, public: data.ip })))
      .catch(() => setNetworkInfo(prev => ({ ...prev, public: "Encrypted / Unavailable" })));

    api.get<{client_ip: string; server_local_ip: string}>("/system/network-info")
      .then(data => setNetworkInfo(prev => ({ ...prev, local: data.server_local_ip })))
      .catch(() => setNetworkInfo(prev => ({ ...prev, local: "Unknown" })));
  }, []);

  const { data: summary, isLoading, isError } = useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: () => api.get<DashboardSummary>("/dashboard/summary"),
    refetchInterval: 5000,
  });
  const { data: trend } = useQuery({
    queryKey: ["dashboard-trend"],
    queryFn: () => api.get<TrendPoint[]>("/dashboard/trend?days=7"),
    enabled: !!summary,
    refetchInterval: 5000,
  });
  const { data: topRisky } = useQuery({
    queryKey: ["top-risky-assets"],
    queryFn: () => api.get<AssetOut[]>("/dashboard/top-risky-assets?limit=5"),
    enabled: !!summary,
    refetchInterval: 5000,
  });
  const { data: geoAssets } = useQuery({
    queryKey: ["geo-assets"],
    queryFn: () => api.get<AssetOut[]>("/dashboard/geo-assets"),
    enabled: !!summary,
    refetchInterval: 5000,
  });
  const { data: scans } = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.get<ScanJobOut[]>("/scans"),
    enabled: !!summary,
    refetchInterval: 5000,
  });
  const { data: systemStatus } = useQuery({
    queryKey: ["system-status"],
    queryFn: () => api.get<SystemStatusOut>("/system/status"),
    enabled: !!summary,
    refetchInterval: 5000,
  });

  const severityData = summary
    ? [
        { name: "Critical", count: summary.findings_by_severity.critical },
        { name: "High", count: summary.findings_by_severity.high },
        { name: "Medium", count: summary.findings_by_severity.medium },
        { name: "Low", count: summary.findings_by_severity.low },
        { name: "Info", count: summary.findings_by_severity.info },
      ]
    : [];

  return (
    <>
      <Topbar title="Security Dashboard" criticalCount={summary?.findings_by_severity.critical ?? 0} />
      <main className="flex-1 overflow-y-auto bg-background p-6 md:p-10">
        {isLoading && <p className="text-sm text-muted">Loading dashboard…</p>}
        {isError && (
          <p className="text-sm text-critical">
            Unable to load dashboard data. Confirm the backend API is running and reachable.
          </p>
        )}

        {summary && (
          <div className="relative z-10 space-y-8 max-w-[1600px] mx-auto">
            <div className="premium-card bg-gradient-to-r from-surface to-surface-hover p-6 flex flex-col md:flex-row items-center justify-between gap-4">
              <div className="premium-card-inner"></div>
              <div className="flex items-center gap-5 relative z-10">
                <div className="premium-glass-icon w-14 h-14 text-primary">
                  <Activity className="h-6 w-6" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-ink tracking-wide">Live Network Link</h3>
                  <div className="flex flex-wrap gap-x-6 gap-y-1 mt-1 text-xs font-medium uppercase tracking-widest text-muted">
                    <p>LOCAL: <span className="font-mono text-ink/80">{networkInfo.local}</span></p>
                    <p>PUBLIC: <span className="font-mono text-ink/80">{networkInfo.public}</span></p>
                  </div>
                </div>
              </div>
              <div className="relative z-10 flex items-center gap-2 px-4 py-1.5 border border-green-500/30 bg-green-500/10 rounded-full text-green-400 font-medium tracking-widest text-xs">
                <span className="h-2 w-2 rounded-full bg-green-500 shadow-[0_0_8px_#22C55E] animate-pulse" /> 
                SECURE UPLINK
              </div>
            </div>

            <div>
              <h2 className="text-2xl font-semibold text-ink tracking-tight">
                Welcome back{user?.full_name ? `, ${user.full_name.split(" ")[0]}` : ""}
              </h2>
              <p className="text-sm text-muted mt-1">Here&apos;s a high-level overview of your network&apos;s security posture today.</p>
            </div>

            <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
              <StatCard icon={Server} label="Total Assets" value={summary.total_assets} accent="text-primary bg-primary/10 border-primary/20" iconColor="text-primary" />
              <StatCard icon={AlertTriangle} label="Open Findings" value={summary.open_findings} accent="text-amber-500 bg-amber-500/10 border-amber-500/20" iconColor="text-amber-500" />
              <StatCard icon={ShieldCheck} label="Critical Risks" value={summary.findings_by_severity.critical} accent="text-red-500 bg-red-500/10 border-red-500/20" iconColor="text-red-500" />
              <StatCard icon={TrendingUp} label="Asset Health" value={`${summary.asset_health_percent}%`} accent="text-emerald-500 bg-emerald-500/10 border-emerald-500/20" iconColor="text-emerald-500" />
              <StatCard icon={ShieldCheck} label="Remediated (30d)" value={summary.remediated_findings_last_30_days} accent="text-blue-500 bg-blue-500/10 border-blue-500/20" iconColor="text-blue-500" />
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              <Card className="premium-card flex flex-col justify-center items-around gap-6 lg:col-span-1 p-6">
                <div className="premium-card-inner"></div>
                <div className="relative z-10 flex justify-around">
                  <ScoreRing score={summary.security_score} label="Security Score" colorClass="#0EA5E9" />
                  <ScoreRing score={summary.risk_score} label="Risk Score" colorClass="#EF4444" />
                </div>
              </Card>

              <Card className="premium-card flex flex-col lg:col-span-1">
                <div className="premium-card-inner"></div>
                <CardHeader className="border-b border-white/5 bg-surface/30 relative z-10"><CardTitle className="text-sm font-medium text-muted">Holographic Shield</CardTitle></CardHeader>
                <div className="flex-1 relative z-10 p-4 flex items-center justify-center">
                  <HolographicShield />
                </div>
              </Card>

              <Card className="premium-card lg:col-span-1 flex flex-col">
                <div className="premium-card-inner"></div>
                <CardHeader className="relative z-10 border-b border-white/5 bg-surface/30">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm font-medium text-muted">Top Risky Assets</CardTitle>
                    <Link href="/assets" className="flex items-center gap-1 text-xs text-primary hover:text-primary/80 transition-colors">
                      View all <ChevronRight size={12} />
                    </Link>
                  </div>
                </CardHeader>
                <div className="p-6 relative z-10 flex-1">
                  {topRisky && topRisky.length > 0 ? (
                    <div className="space-y-4">
                      {topRisky.map((a) => (
                        <div key={a.id} className="flex items-center justify-between text-sm group cursor-default">
                          <div className="min-w-0 flex-1">
                            <p className="truncate text-ink font-medium transition-colors group-hover:text-primary">{a.hostname}</p>
                            <p className="text-xs text-muted/70">{a.site || a.asset_type}</p>
                          </div>
                          <Badge label={a.risk_score >= 66 ? "critical" : a.risk_score >= 33 ? "high" : "low"} />
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-muted/70 text-center mt-4">
                      No risk-scored assets yet.
                    </p>
                  )}
                </div>
              </Card>
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              <Card className="premium-card lg:col-span-2">
                <div className="premium-card-inner"></div>
                <CardHeader className="relative z-10 border-b border-white/5 bg-surface/30"><CardTitle className="text-sm font-medium text-muted">Findings by Severity</CardTitle></CardHeader>
                <div className="relative z-10 p-2"><SeverityDonut data={severityData} /></div>
              </Card>
              <Card className="premium-card">
                <div className="premium-card-inner"></div>
                <CardHeader className="relative z-10 border-b border-white/5 bg-surface/30"><CardTitle className="text-sm font-medium text-muted">Recent Scans</CardTitle></CardHeader>
                <div className="relative z-10"><RecentScans scans={scans || []} /></div>
              </Card>
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              <Card className="premium-card lg:col-span-2">
                <div className="premium-card-inner"></div>
                <CardHeader className="relative z-10 border-b border-white/5 bg-surface/30"><CardTitle className="text-sm font-medium text-muted">Geographic Asset Distribution</CardTitle></CardHeader>
                <div className="relative z-10"><GeoAssetMap assets={geoAssets || []} /></div>
              </Card>
              <Card className="premium-card">
                <div className="premium-card-inner"></div>
                <CardHeader className="relative z-10 border-b border-white/5 bg-surface/30"><CardTitle className="text-sm font-medium text-muted">Risk Trend (Last 7 Days)</CardTitle></CardHeader>
                <div className="relative z-10 p-2"><RiskTrendChart data={trend || []} /></div>
              </Card>
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              <Card className="premium-card flex flex-col">
                <div className="premium-card-inner"></div>
                <CardHeader className="relative z-10 border-b border-white/5 bg-surface/30"><CardTitle className="text-sm font-medium text-muted">Remediation Progress</CardTitle></CardHeader>
                <div className="p-6 relative z-10 flex flex-col justify-center flex-1">
                  <div className="mb-4 h-2 w-full overflow-hidden rounded-full bg-surface-hover shadow-inner">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-primary to-secondary transition-all duration-1000 ease-out shadow-[0_0_10px_rgba(124,58,237,0.5)]"
                      style={{ width: `${summary.remediation_progress_percent}%` }}
                    />
                  </div>
                  <p className="text-3xl font-bold text-ink tracking-tight">{summary.remediation_progress_percent}% <span className="text-sm text-muted font-normal tracking-normal ml-1">remediated</span></p>
                </div>
              </Card>

              <Card className="premium-card lg:col-span-2">
                <div className="premium-card-inner"></div>
                <CardHeader className="relative z-10 border-b border-white/5 bg-surface/30"><CardTitle className="text-sm font-medium text-muted">Compliance Overview</CardTitle></CardHeader>
                <div className="relative z-10"><ComplianceRings status={summary.compliance_status} /></div>
              </Card>
            </div>

            {systemStatus && (
              <Card className="premium-card">
                <div className="premium-card-inner"></div>
                <CardHeader className="relative z-10 border-b border-white/5 bg-surface/30">
                  <CardTitle className="text-sm font-medium text-muted flex items-center gap-2">
                    <div className="h-2 w-2 bg-green-500 rounded-full shadow-[0_0_8px_rgba(34,197,94,0.6)] animate-pulse"/> System Status
                  </CardTitle>
                </CardHeader>
                <div className="relative z-10"><SystemStatusWidget overallStatus={systemStatus.overall_status} components={systemStatus.components} /></div>
              </Card>
            )}

            <Card className="premium-card lg:col-span-3">
              <div className="premium-card-inner"></div>
              <CardHeader className="relative z-10 border-b border-white/5 bg-surface/30">
                <CardTitle className="text-sm font-medium text-muted flex items-center gap-2">
                  <Activity size={16} className="text-secondary" /> Live Threat Activity Ticker
                </CardTitle>
              </CardHeader>
              <div className="relative z-10"><ActivityTicker /></div>
            </Card>
          </div>
        )}
      </main>
    </>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
  accent,
  iconColor
}: {
  icon: typeof AlertTriangle;
  label: string;
  value: string | number;
  accent: string;
  iconColor?: string;
}) {
  return (
    <Card className="premium-card p-5 hover:border-white/10 group cursor-default">
      <div className="premium-card-inner"></div>
      <div className="flex flex-col relative z-10 h-full">
        <div className="flex items-start justify-between mb-4">
          <div className={`p-2.5 rounded-xl border ${accent} transition-transform duration-300 group-hover:scale-110 shadow-sm`}>
            <Icon size={18} className="opacity-90" />
          </div>
        </div>
        <div className="mt-auto">
          <p className="text-2xl font-bold tracking-tight text-ink mb-1">{value}</p>
          <p className="text-xs font-medium text-muted">{label}</p>
        </div>
      </div>
    </Card>
  );
}
