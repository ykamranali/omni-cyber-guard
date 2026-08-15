"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard, Server, ShieldAlert, FileCheck2, FileBarChart2,
  Settings, ShieldCheck, Users, Building2, ScrollText, BadgeDollarSign, Radar, Satellite,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/store/auth";

const NAV_ITEMS = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard, enabled: true },
  { href: "/assets", label: "Assets", icon: Server, enabled: true },
  { href: "/scans", label: "Scan Center", icon: Radar, enabled: true, requires: "scans" as const },
  { href: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert, enabled: true },
  { href: "/compliance", label: "Compliance", icon: FileCheck2, enabled: false },
  { href: "/reports", label: "Reports", icon: FileBarChart2, enabled: false },
  { href: "/threat-intelligence", label: "Threat Intelligence", icon: Satellite, enabled: false },
  { href: "/users", label: "Users", icon: Users, enabled: true, requires: "users" as const },
  { href: "/organizations", label: "Organizations", icon: Building2, enabled: true, requires: "super_admin" as const },
  { href: "/settings", label: "Settings", icon: Settings, enabled: false },
  { href: "/audit-logs", label: "Audit Logs", icon: ScrollText, enabled: false },
  { href: "/licensing", label: "Licensing", icon: BadgeDollarSign, enabled: false },
];

export function Sidebar() {
  const pathname = usePathname();
  const user = useAuthStore((s) => s.user);

  const visibleItems = NAV_ITEMS.filter((item) => {
    if (item.requires === "super_admin") return !!user?.is_super_admin;
    // "Users" management is shown to anyone whose role set isn't just read-only/auditor —
    // the backend still enforces MANAGE_USERS on every request regardless of what's shown here.
    if (item.requires === "users") {
      return user?.is_super_admin || user?.roles?.some((r) => ["organization_administrator", "security_manager"].includes(r));
    }
    // Scan Center is shown to roles that hold RUN_SCANS in the backend RBAC defaults
    // (organization_administrator, security_manager, security_analyst). The API still
    // enforces the real permission on every request regardless of what's shown here.
    if (item.requires === "scans") {
      return (
        user?.is_super_admin ||
        user?.roles?.some((r) => ["organization_administrator", "security_manager", "security_analyst"].includes(r))
      );
    }
    return true;
  });

  return (
    <aside className="hidden w-64 flex-col border-r border-border bg-surface/40 backdrop-blur-xl md:flex">
      <div className="flex h-16 items-center gap-2 border-b border-border px-5">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-primary to-secondary">
          <ShieldCheck className="h-4 w-4 text-white" />
        </div>
        <div>
          <p className="text-sm font-semibold leading-none text-ink">Omni Cyber Guard</p>
        </div>
      </div>

      <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-4">
        {visibleItems.map(({ href, label, icon: Icon, enabled }) => {
          const active = pathname === href || pathname.startsWith(href + "/");

          if (!enabled) {
            return (
              <div
                key={href}
                title="Coming in a future milestone"
                className="flex cursor-not-allowed items-center justify-between rounded-lg px-3 py-2.5 text-sm font-medium text-muted"
              >
                <span className="flex items-center gap-3">
                  <Icon size={17} />
                  {label}
                </span>
                <span className="rounded-full border border-border px-1.5 py-0.5 text-[9px] uppercase tracking-wide text-muted">
                  Soon
                </span>
              </div>
            );
          }

          return (
            <Link
              key={href}
              href={href}
              className={cn(
                "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors",
                active
                  ? "bg-primary/15 text-primary border border-primary/30"
                  : "text-ink/75 hover:bg-surface-hover hover:text-ink"
              )}
            >
              <Icon size={17} />
              {label}
            </Link>
          );
        })}
      </nav>

      <div className="border-t border-border p-4 text-center text-[11px] text-muted">
        Powered by Omni Digital Solution
      </div>
    </aside>
  );
}
