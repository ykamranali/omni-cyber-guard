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
  });
  const { data: trend } = useQuery({
    queryKey: ["dashboard-trend"],
    queryFn: () => api.get<TrendPoint[]>("/dashboard/trend?days=7"),
    enabled: !!summary,
  });
  const { data: topRisky } = useQuery({
    queryKey: ["top-risky-assets"],
    queryFn: () => api.get<AssetOut[]>("/dashboard/top-risky-assets?limit=5"),
    enabled: !!summary,
  });
  const { data: geoAssets } = useQuery({
    queryKey: ["geo-assets"],
    queryFn: () => api.get<AssetOut[]>("/dashboard/geo-assets"),
    enabled: !!summary,
  });
  const { data: scans } = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.get<ScanJobOut[]>("/scans"),
    enabled: !!summary,
  });
  const { data: systemStatus } = useQuery({
    queryKey: ["system-status"],
    queryFn: () => api.get<SystemStatusOut>("/system/status"),
    enabled: !!summary,
    refetchInterval: 30_000,
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
      <main className="flex-1 overflow-y-auto bg-background blueprint-grid p-4 md:p-8">
        {isLoading && <p className="text-sm text-muted">Loading dashboard…</p>}
        {isError && (
          <p className="text-sm text-critical">
            Unable to load dashboard data. Confirm the backend API is running and reachable.
          </p>
        )}

        {summary && (
          <div className="relative z-10 space-y-6">
            <div className="network-lightning-bg hud-panel p-6 border-primary/50 flex flex-col md:flex-row items-center justify-between mb-6 gap-4">
              <div className="flex items-center gap-4 relative z-10">
                <div className="p-3 border border-primary text-primary shadow-[inset_0_0_10px_rgba(14,165,233,0.5)] bg-surface/80">
                  <Activity className="h-8 w-8 animate-pulse-glow" />
                </div>
                <div>
                  <h3 className="text-xl font-bold neon-text text-primary tracking-widest">LIVE NETWORK LINK</h3>
                  <div className="flex flex-wrap gap-x-6 gap-y-1 mt-2 text-sm font-semibold uppercase tracking-wider text-muted">
                    <p>LOCAL NODE: <span className="font-mono text-ink bg-surface-hover px-2 py-0.5 rounded ml-1">{networkInfo.local}</span></p>
                    <p>PUBLIC IP: <span className="font-mono text-ink bg-surface-hover px-2 py-0.5 rounded ml-1">{networkInfo.public}</span></p>
                  </div>
                </div>
              </div>
              <div className="relative z-10 flex items-center gap-2 px-4 py-2 border border-green-500/50 bg-green-500/10 rounded-full text-green-500 font-bold tracking-widest text-xs shadow-[0_0_15px_rgba(34,197,94,0.4)]">
                <span className="h-2.5 w-2.5 rounded-full bg-green-500 animate-pulse-glow shadow-[0_0_8px_#22C55E]" /> 
                SECURE UPLINK ACTIVE
              </div>
            </div>

            <div>
              <h2 className="text-xl font-semibold text-ink neon-text">
                Welcome back{user?.full_name ? `, ${user.full_name.split(" ")[0]}` : ""}
              </h2>
              <p className="text-sm text-muted uppercase tracking-wider font-bold">Here&apos;s what&apos;s happening in your network grid today.</p>
            </div>

            <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
              <StatCard icon={Server} label="Total Assets" value={summary.total_assets} accent="text-primary" sysCode="SYS:001" />
              <StatCard icon={AlertTriangle} label="Open Findings" value={summary.open_findings} accent="text-high" sysCode="SYS:002" />
              <StatCard icon={ShieldCheck} label="Critical Risks" value={summary.findings_by_severity.critical} accent="text-critical" sysCode="SYS:003" />
              <StatCard icon={TrendingUp} label="Asset Health" value={`${summary.asset_health_percent}%`} accent="text-low" sysCode="SYS:004" />
              <StatCard icon={ShieldCheck} label="Remediated (30d)" value={summary.remediated_findings_last_30_days} accent="text-low" sysCode="SYS:005" />
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              <Card className="hud-panel flex items-center justify-around gap-4 lg:col-span-1">
                <ScoreRing score={summary.security_score} label="Security Score" colorClass="#0EA5E9" />
                <ScoreRing score={summary.risk_score} label="Risk Score" colorClass="#EF4444" />
              </Card>

              <Card className="hud-panel flex flex-col lg:col-span-1 relative overflow-hidden">
                <CardHeader className="border-b border-primary/20 bg-surface/50"><CardTitle className="font-mono text-sm tracking-widest text-primary">HOLOGRAPHIC SHIELD</CardTitle></CardHeader>
                <div className="flex-1 relative z-10 p-4">
                  <HolographicShield />
                </div>
              </Card>

              <Card className="hud-panel lg:col-span-1">
                <CardHeader>
                  <CardTitle>Top Risky Assets</CardTitle>
                  <Link href="/assets" className="flex items-center gap-1 text-xs text-primary hover:underline">
                    View all <ChevronRight size={12} />
                  </Link>
                </CardHeader>
                {topRisky && topRisky.length > 0 ? (
                  <div className="space-y-2">
                    {topRisky.map((a) => (
                      <div key={a.id} className="flex items-center justify-between text-sm">
                        <div className="min-w-0">
                          <p className="truncate text-ink/85">{a.hostname}</p>
                          <p className="text-xs text-muted">{a.site || a.asset_type}</p>
                        </div>
                        <Badge label={a.risk_score >= 66 ? "critical" : a.risk_score >= 33 ? "high" : "low"} />
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-muted">
                    No risk-scored assets yet — risk scores are computed from real findings, so this fills in as you add findings or run a scan.
                  </p>
                )}
              </Card>
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              <Card className="hud-panel lg:col-span-2">
                <CardHeader><CardTitle>Findings by Severity</CardTitle></CardHeader>
                <SeverityDonut data={severityData} />
              </Card>
              <Card className="hud-panel">
                <CardHeader><CardTitle>Recent Scans</CardTitle></CardHeader>
                <RecentScans scans={scans || []} />
              </Card>
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              <Card className="hud-panel lg:col-span-2">
                <CardHeader>
                  <CardTitle>Geographic Asset Distribution</CardTitle>
                </CardHeader>
                <GeoAssetMap assets={geoAssets || []} />
              </Card>
              <Card className="hud-panel">
                <CardHeader><CardTitle>Risk Trend (Last 7 Days)</CardTitle></CardHeader>
                <RiskTrendChart data={trend || []} />
              </Card>
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              <Card className="hud-panel">
                <CardHeader><CardTitle>Remediation Progress</CardTitle></CardHeader>
                <div className="mb-2 h-3 w-full overflow-hidden rounded-full bg-surface-hover border border-primary/20">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-primary to-secondary shadow-neon"
                    style={{ width: `${summary.remediation_progress_percent}%` }}
                  />
                </div>
                <p className="text-sm font-semibold neon-text text-primary">{summary.remediation_progress_percent}% <span className="text-muted font-normal">of all findings remediated</span></p>
              </Card>

              <Card className="hud-panel lg:col-span-2">
                <CardHeader><CardTitle>Compliance Overview</CardTitle></CardHeader>
                <ComplianceRings status={summary.compliance_status} />
              </Card>
            </div>

            {systemStatus && (
              <Card className="hud-panel border-primary/50 shadow-neon">
                <CardHeader><CardTitle className="neon-text text-primary flex items-center gap-2"><div className="h-2 w-2 bg-primary rounded-full animate-pulse-glow"/> System Status</CardTitle></CardHeader>
                <SystemStatusWidget overallStatus={systemStatus.overall_status} components={systemStatus.components} />
              </Card>
            )}
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
  sysCode
}: {
  icon: typeof AlertTriangle;
  label: string;
  value: string | number;
  accent: string;
  sysCode?: string;
}) {
  return (
    <Card className={`hud-panel relative group hover:border-primary/80 transition-colors bg-surface/90 p-4`}>
      <div className="flex items-center justify-between gap-4 relative z-10">
        <div>
          <p className="text-[10px] tracking-widest uppercase text-primary font-mono mb-1">{sysCode || 'SYS:001'}</p>
          <p className={`text-3xl font-bold tracking-tight font-mono neon-text ${accent}`}>{value}</p>
          <p className="text-[10px] tracking-widest uppercase text-muted font-bold mt-1">{label}</p>
        </div>
        <div className={`p-3 border border-current shadow-[inset_0_0_10px_currentColor] transition-transform group-hover:scale-110 ${accent}`}>
          <Icon size={22} className="animate-pulse-glow" />
        </div>
      </div>
      {/* Tech bar chart background */}
      <div className={`absolute bottom-2 right-2 flex items-end gap-[2px] opacity-20 ${accent} z-0`}>
        <div className="w-1.5 h-3 bg-current" />
        <div className="w-1.5 h-6 bg-current" />
        <div className="w-1.5 h-2 bg-current" />
        <div className="w-1.5 h-8 bg-current" />
        <div className="w-1.5 h-5 bg-current" />
      </div>
    </Card>
  );
}
