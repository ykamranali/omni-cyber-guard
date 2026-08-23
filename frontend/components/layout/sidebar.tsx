"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity, BadgeDollarSign, BrainCircuit, Building2, Cloud, DatabaseZap, FileBarChart2,
  FileCheck2, Fingerprint, Globe, KeyRound, LayoutDashboard, Network, Radar,
  ScrollText, Server, Settings, ShieldAlert, ShieldCheck, Share2, Satellite,
  Users, Wrench, ChevronDown, ChevronRight
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/store/auth";
import { useBranding } from "@/components/providers/branding-provider";

type Requirement = "super_admin" | "users" | "scans" | "credentials";

interface NavItem {
  href: string;
  label: string;
  icon: typeof LayoutDashboard;
  built: boolean;
  requires?: Requirement;
}

interface NavGroup {
  title: string;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    title: "Overview",
    items: [
      { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard, built: true },
      { href: "/exposure", label: "Exposure Overview", icon: Activity, built: true },
    ],
  },
  {
    title: "Discovery",
    items: [
      { href: "/assets", label: "Assets", icon: Server, built: true },
      { href: "/networks", label: "Sites & Networks", icon: Network, built: true },
      { href: "/attack-surface", label: "Attack Surface", icon: Globe, built: true },
      { href: "/cloud", label: "Cloud Assets", icon: Cloud, built: true },
      { href: "/identity", label: "Identity", icon: Fingerprint, built: true },
    ],
  },
  {
    title: "Assessment",
    items: [
      { href: "/scans", label: "Scan Center", icon: Radar, built: true, requires: "scans" },
      { href: "/vulnerabilities", label: "Findings", icon: ShieldAlert, built: true },
      { href: "/compliance", label: "Compliance", icon: FileCheck2, built: true },
    ],
  },
  {
    title: "Exposure",
    items: [
      { href: "/exposure-graph", label: "Exposure Graph", icon: Share2, built: true },
      { href: "/attack-paths", label: "Attack Paths", icon: Share2, built: true },
    ],
  },
  {
    title: "Intelligence",
    items: [
      { href: "/threat-intelligence", label: "Threat Intelligence", icon: Satellite, built: true },
      { href: "/intelligence", label: "Correlated Intelligence", icon: BrainCircuit, built: true },
      { href: "/cve-intelligence", label: "CVE Intelligence", icon: DatabaseZap, built: true },
    ],
  },
  {
    title: "Operations",
    items: [
      { href: "/remediation", label: "Remediation", icon: Wrench, built: true },
      { href: "/incidents", label: "Incident Response", icon: ShieldAlert, built: true },
      { href: "/infrastructure", label: "Infrastructure Protection", icon: ShieldCheck, built: true },
      { href: "/ask-agent", label: "Ask Omni Agent", icon: BrainCircuit, built: true },
    ],
  },
  {
    title: "Reporting",
    items: [
      { href: "/reports", label: "Reports", icon: FileBarChart2, built: true },
    ],
  },
  {
    title: "Administration",
    items: [
      { href: "/organizations", label: "Organizations", icon: Building2, built: true, requires: "super_admin" },
      { href: "/users", label: "Users", icon: Users, built: true, requires: "users" },
      { href: "/credentials", label: "Credentials", icon: KeyRound, built: true, requires: "credentials" },
      { href: "/settings", label: "Settings", icon: Settings, built: true },
      { href: "/audit-logs", label: "Audit Logs", icon: ScrollText, built: true },
      { href: "/licensing", label: "Licensing", icon: BadgeDollarSign, built: true },
    ],
  },
];

function isVisible(item: NavItem, user: ReturnType<typeof useAuthStore.getState>["user"]): boolean {
  if (!item.requires) return true;
  if (user?.is_super_admin) return true;

  const roles = user?.roles ?? [];
  switch (item.requires) {
    case "super_admin":
      return false;
    case "users":
      return roles.some((r) => ["organization_administrator", "security_manager"].includes(r));
    case "credentials":
      return roles.some((r) => r === "organization_administrator");
    case "scans":
      return roles.some((r) =>
        ["organization_administrator", "security_manager", "security_analyst"].includes(r)
      );
    default:
      return true;
  }
}

export function Sidebar() {
  const pathname = usePathname();
  const user = useAuthStore((s) => s.user);
  const { branding } = useBranding();

  // Initialize expanded state: expand the group that contains the current active route
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  useEffect(() => {
    const initialState: Record<string, boolean> = {};
    NAV_GROUPS.forEach((group) => {
      // expand if any child is active
      // Groups containing the current route open; the rest stay collapsed.
      // This line previously read `hasActive || true`, so the condition was
      // computed and discarded and every group was always open.
      initialState[group.title] = group.items.some(
        (item) => pathname === item.href || pathname.startsWith(item.href + "/"),
      );
    });
    setExpanded(initialState);
  }, [pathname]);

  const toggleGroup = (title: string) => {
    setExpanded((prev) => ({ ...prev, [title]: !prev[title] }));
  };

  return (
    <aside className="hidden w-64 flex-col border-r border-border bg-surface/40 backdrop-blur-xl md:flex">
      <div className="relative flex h-20 items-center gap-3 overflow-hidden border-b border-primary/20 bg-surface/20 px-5 shadow-[0_4px_20px_rgba(var(--color-primary)/0.1)]">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(var(--color-primary)/0.15),transparent_70%)]" />
        <div className="glossy-icon z-10 flex h-10 w-10 items-center justify-center overflow-hidden rounded-xl border border-primary/40 text-primary shadow-neon">
          {branding.logo_url ? (
            /* eslint-disable-next-line @next/next/no-img-element */
            <img
              src={branding.logo_url}
              alt={branding.name}
              className="h-full w-full object-contain"
              onError={(event) => {
                // A broken logo URL must not leave an empty box where the
                // brand mark should be.
                event.currentTarget.style.display = "none";
              }}
            />
          ) : (
            <ShieldCheck className="h-6 w-6" />
          )}
        </div>
        <div className="z-10 min-w-0">
          <p className="neon-text truncate text-[15px] font-bold uppercase tracking-wider text-ink">
            {branding.name}
          </p>
        </div>
      </div>

      <nav className="flex-1 space-y-2 overflow-y-auto px-3 py-4">
        {NAV_GROUPS.map((group) => {
          const items = group.items.filter((item) => isVisible(item, user));
          if (items.length === 0) return null;

          const isExpanded = expanded[group.title];

          return (
            <div key={group.title} className="mb-2">
              <button
                onClick={() => toggleGroup(group.title)}
                className="flex w-full items-center justify-between px-3 py-1.5 text-left transition-colors hover:bg-surface-hover rounded-lg group/btn"
              >
                <span className="text-[10px] font-bold uppercase tracking-[0.15em] text-muted/80 group-hover/btn:text-ink transition-colors">
                  {group.title}
                </span>
                <span className="text-muted/50 transition-colors group-hover/btn:text-muted">
                  {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                </span>
              </button>
              
              <div className={cn("mt-1 space-y-0.5 overflow-hidden transition-all duration-300 ease-in-out", isExpanded ? "max-h-[500px] opacity-100" : "max-h-0 opacity-0")}>
                {items.map(({ href, label, icon: Icon, built }) => {
                  const active = pathname === href || pathname.startsWith(href + "/");

                  if (!built) {
                    return (
                      <div
                        key={href}
                        title="This module is not implemented yet"
                        className="flex cursor-not-allowed items-center justify-between rounded-lg px-3 py-2 text-sm font-medium text-muted/40"
                      >
                        <span className="flex items-center gap-3">
                          <span className="rounded-lg p-1.5">
                            <Icon size={16} />
                          </span>
                          {label}
                        </span>
                        <span className="rounded-full border border-border/50 px-1.5 py-0.5 text-[9px] uppercase tracking-wide text-muted/50">
                          Not built
                        </span>
                      </div>
                    );
                  }

                  return (
                    <Link
                      key={href}
                      href={href}
                      className={cn(
                        "group relative flex items-center gap-3 overflow-hidden rounded-lg px-3 py-2 text-sm font-medium transition-all duration-200",
                        active
                          ? "neon-pulse-border border border-primary/50 bg-primary/15 text-primary shadow-[inset_0_0_20px_rgba(var(--color-primary)/0.3)]"
                          : "text-ink/70 hover:bg-surface-hover hover:text-ink"
                      )}
                    >
                      {active && (
                        <div className="pointer-events-none absolute inset-0 bg-gradient-to-r from-primary/10 to-transparent" />
                      )}
                      <div
                        className={cn(
                          "z-10 rounded-lg p-1.5 transition-all duration-300",
                          active
                            ? "glossy-icon border border-primary shadow-[0_0_10px_rgba(var(--color-primary)/0.5)] bg-primary/10"
                            : "bg-surface group-hover:glossy-icon border border-transparent"
                        )}
                      >
                        <Icon size={15} className={cn(active && "drop-shadow-[0_0_8px_rgba(var(--color-primary)/0.8)]")} />
                      </div>
                      <span className={cn("z-10 tracking-wide transition-colors", active ? "neon-text font-bold" : "group-hover:text-ink font-medium")}>
                        {label}
                      </span>
                    </Link>
                  );
                })}
              </div>
            </div>
          );
        })}
      </nav>

      <div className="border-t border-border bg-surface/30 p-4 text-center text-[10px] uppercase tracking-wider text-muted/60">
        {branding.footer_text}
      </div>
    </aside>
  );
}
