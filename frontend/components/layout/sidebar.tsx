"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity, BadgeDollarSign, BrainCircuit, Building2, Cloud, DatabaseZap, FileBarChart2,
  FileCheck2, Fingerprint, Globe, KeyRound, LayoutDashboard, Network, Radar,
  ScrollText, Server, Settings, ShieldAlert, ShieldCheck, Share2, Satellite,
  Users, Wrench,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/store/auth";

type Requirement = "super_admin" | "users" | "scans" | "credentials";

interface NavItem {
  href: string;
  label: string;
  icon: typeof LayoutDashboard;
  /**
   * `false` means the module is not built yet. It renders as a disabled row
   * rather than a link to a page that would only look functional.
   */
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
      { href: "/attack-surface", label: "Attack Surface", icon: Globe, built: false },
      { href: "/cloud", label: "Cloud Assets", icon: Cloud, built: false },
      { href: "/identity", label: "Identity", icon: Fingerprint, built: false },
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
      { href: "/exposure-graph", label: "Exposure Graph", icon: Share2, built: false },
      { href: "/attack-paths", label: "Attack Paths", icon: Share2, built: false },
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

/**
 * Role gates below only hide navigation. Every request is authorized again on
 * the backend, so hiding a link is a convenience, never the control.
 */
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
      // MANAGE_API_KEYS in the backend RBAC defaults.
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

  return (
    <aside className="hidden w-64 flex-col border-r border-border bg-surface/40 backdrop-blur-xl md:flex">
      <div className="relative flex h-20 items-center gap-3 overflow-hidden border-b border-primary/20 bg-surface/20 px-5 shadow-[0_4px_20px_rgba(var(--color-primary)/0.1)]">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(var(--color-primary)/0.15),transparent_70%)]" />
        <div className="glossy-icon z-10 h-10 w-10 rounded-xl border border-primary/40 text-primary shadow-neon">
          <ShieldCheck className="h-6 w-6" />
        </div>
        <div className="z-10">
          <p className="neon-text text-[15px] font-bold uppercase tracking-wider text-ink">
            Omni Cyber Guard
          </p>
        </div>
      </div>

      <nav className="flex-1 space-y-5 overflow-y-auto px-3 py-4">
        {NAV_GROUPS.map((group) => {
          const items = group.items.filter((item) => isVisible(item, user));
          if (items.length === 0) return null;

          return (
            <div key={group.title}>
              <p className="mb-1.5 px-3 text-[10px] font-bold uppercase tracking-[0.15em] text-muted/70">
                {group.title}
              </p>
              <div className="space-y-0.5">
                {items.map(({ href, label, icon: Icon, built }) => {
                  const active = pathname === href || pathname.startsWith(href + "/");

                  if (!built) {
                    return (
                      <div
                        key={href}
                        title="This module is not implemented yet"
                        className="flex cursor-not-allowed items-center justify-between rounded-lg px-3 py-2 text-sm font-medium text-muted/50"
                      >
                        <span className="flex items-center gap-3">
                          <span className="rounded-lg p-1.5">
                            <Icon size={16} />
                          </span>
                          {label}
                        </span>
                        <span className="rounded-full border border-border px-1.5 py-0.5 text-[9px] uppercase tracking-wide text-muted/60">
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
                        "group relative flex items-center gap-3 overflow-hidden rounded-lg px-3 py-2 text-sm font-medium transition-all duration-300",
                        active
                          ? "neon-pulse-border border border-primary/50 bg-primary/15 text-primary shadow-[inset_0_0_20px_rgba(var(--color-primary)/0.3)]"
                          : "text-ink/75 hover:translate-x-1 hover:bg-surface-hover hover:text-ink"
                      )}
                    >
                      {active && (
                        <div className="pointer-events-none absolute inset-0 bg-gradient-to-r from-primary/20 to-transparent" />
                      )}
                      <div
                        className={cn(
                          "z-10 rounded-lg p-1.5 transition-all duration-300",
                          active
                            ? "glossy-icon border border-primary shadow-[0_0_10px_rgba(var(--color-primary)/0.5)]"
                            : "bg-surface group-hover:glossy-icon"
                        )}
                      >
                        <Icon size={15} className={cn(active && "drop-shadow-md")} />
                      </div>
                      <span className={cn("z-10 tracking-wide", active && "neon-text font-bold")}>
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

      <div className="border-t border-border p-4 text-center text-[11px] text-muted">
        Powered by Omni Digital Solution
      </div>
    </aside>
  );
}
