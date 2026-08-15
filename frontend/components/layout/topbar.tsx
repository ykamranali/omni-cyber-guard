"use client";

import { useRouter } from "next/navigation";
import { Bell, LogOut, ChevronDown, Search, Maximize, Minimize, Sun, Moon } from "lucide-react";
import { useState, KeyboardEvent } from "react";
import { useAuthStore } from "@/store/auth";
import { useThemeStore } from "@/store/theme";

export function Topbar({ title, criticalCount = 0 }: { title: string; criticalCount?: number }) {
  const router = useRouter();
  const user = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);
  const { theme, toggleTheme } = useThemeStore();
  const [menuOpen, setMenuOpen] = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);
  const [searchValue, setSearchValue] = useState("");
  const [isFullscreen, setIsFullscreen] = useState(false);

  function handleLogout() {
    logout();
    router.push("/login");
  }

  function handleSearchKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" && searchValue.trim()) {
      router.push(`/assets?search=${encodeURIComponent(searchValue.trim())}`);
    }
  }

  function toggleFullscreen() {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen?.();
      setIsFullscreen(true);
    } else {
      document.exitFullscreen?.();
      setIsFullscreen(false);
    }
  }

  return (
    <header className="flex h-16 items-center justify-between gap-4 border-b border-border bg-surface/30 px-6 backdrop-blur-xl">
      <h1 className="shrink-0 text-lg font-semibold text-ink">{title}</h1>

      <div className="relative hidden max-w-sm flex-1 md:block">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
        <input
          value={searchValue}
          onChange={(e) => setSearchValue(e.target.value)}
          onKeyDown={handleSearchKeyDown}
          placeholder="Search assets… (press Enter)"
          className="h-9 w-full rounded-lg border border-border bg-background/60 pl-9 pr-3 text-sm text-ink placeholder:text-muted focus:outline-none focus:ring-2 focus:ring-primary/40"
        />
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={toggleTheme}
          title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          className="rounded-lg p-2 text-ink/75 hover:bg-surface-hover"
        >
          {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
        </button>

        <button
          onClick={toggleFullscreen}
          title={isFullscreen ? "Exit fullscreen" : "Enter fullscreen"}
          className="hidden rounded-lg p-2 text-ink/75 hover:bg-surface-hover sm:block"
        >
          {isFullscreen ? <Minimize size={17} /> : <Maximize size={17} />}
        </button>

        <div className="relative">
          <button
            onClick={() => setNotifOpen((v) => !v)}
            className="relative rounded-lg p-2 text-ink/75 hover:bg-surface-hover"
          >
            <Bell size={18} />
            {criticalCount > 0 && (
              <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-critical px-1 text-[10px] font-semibold text-white">
                {criticalCount > 9 ? "9+" : criticalCount}
              </span>
            )}
          </button>
          {notifOpen && (
            <div className="absolute right-0 top-12 w-64 rounded-lg border border-border bg-surface p-3 shadow-glass">
              <p className="text-sm text-ink/85">
                {criticalCount > 0
                  ? `${criticalCount} critical finding${criticalCount === 1 ? "" : "s"} need attention.`
                  : "No critical findings right now."}
              </p>
              <p className="mt-1 text-xs text-muted">See the Vulnerabilities page for details.</p>
            </div>
          )}
        </div>

        <div className="relative">
          <button
            onClick={() => setMenuOpen((v) => !v)}
            className="flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-surface-hover"
          >
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-gradient-to-br from-primary to-secondary text-xs font-semibold text-white">
              {user?.full_name?.slice(0, 2).toUpperCase() || "OG"}
            </div>
            <div className="hidden text-left sm:block">
              <p className="text-sm font-medium leading-none text-ink">{user?.full_name || "User"}</p>
              <p className="text-xs text-muted">{user?.roles?.[0]?.replace(/_/g, " ") || ""}</p>
            </div>
            <ChevronDown size={14} className="text-muted" />
          </button>

          {menuOpen && (
            <div className="absolute right-0 top-12 w-48 rounded-lg border border-border bg-surface p-1 shadow-glass">
              <button
                onClick={handleLogout}
                className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm text-ink/75 hover:bg-surface-hover"
              >
                <LogOut size={15} /> Sign out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
