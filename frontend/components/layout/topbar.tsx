"use client";

import { useRouter } from "next/navigation";
import { Bell, LogOut, ChevronDown, Search, Maximize, Minimize, Sun, Moon } from "lucide-react";
import { useState, KeyboardEvent, useEffect, useRef } from "react";
import { useAuthStore } from "@/store/auth";
import { useThemeStore } from "@/store/theme";
import { api } from "@/lib/api";
import Link from "next/link";

export function Topbar({ title, criticalCount = 0 }: { title: string; criticalCount?: number }) {
  const router = useRouter();
  const user = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);
  const { theme, toggleTheme } = useThemeStore();
  const [menuOpen, setMenuOpen] = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);
  const [searchValue, setSearchValue] = useState("");
  const [isFullscreen, setIsFullscreen] = useState(false);

  const [searchResults, setSearchResults] = useState<any>(null);
  const [notifications, setNotifications] = useState<any[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const searchTimeoutRef = useRef<NodeJS.Timeout>();

  useEffect(() => {
    // Fetch initial notifications
    if (user) {
      api.get<any>("/notifications").then((data) => {
        setNotifications(data.items);
        setUnreadCount(data.unread_count);
      }).catch(console.error);
    }
  }, [user]);

  function handleLogout() {
    logout();
    router.push("/login");
  }

  function handleSearchChange(val: string) {
    setSearchValue(val);
    if (searchTimeoutRef.current) clearTimeout(searchTimeoutRef.current);
    
    if (!val.trim()) {
      setSearchResults(null);
      return;
    }
    
    searchTimeoutRef.current = setTimeout(async () => {
      try {
        const results = await api.get<any>(`/search?q=${encodeURIComponent(val)}`);
        setSearchResults(results);
      } catch (err) {
        console.error("Search failed", err);
      }
    }, 300);
  }

  async function handleMarkRead(id: string) {
    try {
      await api.patch(`/notifications/${id}/read`);
      setNotifications(prev => prev.map(n => n.id === id ? { ...n, read_at: new Date().toISOString() } : n));
      setUnreadCount(prev => Math.max(0, prev - 1));
    } catch (err) {
      console.error(err);
    }
  }

  function handleSearchKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" && searchValue.trim()) {
      setSearchResults(null);
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
          onChange={(e) => handleSearchChange(e.target.value)}
          onKeyDown={handleSearchKeyDown}
          onBlur={() => setTimeout(() => setSearchResults(null), 200)}
          placeholder="Global search… (press Enter for assets)"
          className="h-9 w-full rounded-lg border border-border bg-background/60 pl-9 pr-3 text-sm text-ink placeholder:text-muted focus:outline-none focus:ring-2 focus:ring-primary/40"
        />
        {searchResults && (
          <div className="absolute left-0 top-12 max-h-[70vh] w-[500px] overflow-y-auto rounded-lg border border-border bg-surface p-2 shadow-glass z-50">
            {searchResults.assets?.length > 0 && (
              <div className="mb-2">
                <h3 className="px-2 pb-1 text-xs font-semibold uppercase text-muted">Assets</h3>
                {searchResults.assets.map((a: any) => (
                  <Link key={a.id} href={`/assets/${a.id}`} className="block rounded-md px-2 py-1.5 hover:bg-surface-hover">
                    <p className="text-sm font-medium text-ink">{a.hostname}</p>
                    <p className="text-xs text-muted">{a.ip_address}</p>
                  </Link>
                ))}
              </div>
            )}
            {searchResults.findings?.length > 0 && (
              <div className="mb-2">
                <h3 className="px-2 pb-1 text-xs font-semibold uppercase text-muted">Findings</h3>
                {searchResults.findings.map((f: any) => (
                  <Link key={f.id} href={`/vulnerabilities`} className="block rounded-md px-2 py-1.5 hover:bg-surface-hover">
                    <p className="text-sm font-medium text-ink">{f.title}</p>
                    <p className="text-xs text-muted">{f.severity} • {f.status}</p>
                  </Link>
                ))}
              </div>
            )}
            {searchResults.cves?.length > 0 && (
              <div className="mb-2">
                <h3 className="px-2 pb-1 text-xs font-semibold uppercase text-muted">CVE Intel</h3>
                {searchResults.cves.map((c: any) => (
                  <Link key={c.id} href={`/cve-intelligence/${c.id}`} className="block rounded-md px-2 py-1.5 hover:bg-surface-hover">
                    <p className="text-sm font-medium text-ink">{c.id}</p>
                    <p className="text-xs text-muted truncate">{c.description}</p>
                  </Link>
                ))}
              </div>
            )}
            {(!searchResults.assets?.length && !searchResults.findings?.length && !searchResults.cves?.length) && (
              <p className="p-4 text-center text-sm text-muted">No results found.</p>
            )}
          </div>
        )}
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
            {unreadCount > 0 && (
              <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-critical px-1 text-[10px] font-semibold text-white">
                {unreadCount > 9 ? "9+" : unreadCount}
              </span>
            )}
          </button>
          {notifOpen && (
            <div className="absolute right-0 top-12 w-80 max-h-[60vh] overflow-y-auto rounded-lg border border-border bg-surface shadow-glass z-50">
              <div className="border-b border-border p-3 sticky top-0 bg-surface/90 backdrop-blur-sm flex justify-between items-center">
                <h3 className="text-sm font-semibold text-ink">Notifications</h3>
                {unreadCount > 0 && (
                  <button onClick={async () => {
                    await api.post("/notifications/read-all");
                    setNotifications(prev => prev.map(n => ({ ...n, read_at: new Date().toISOString() })));
                    setUnreadCount(0);
                  }} className="text-xs text-primary hover:underline">Mark all read</button>
                )}
              </div>
              <div className="p-2">
                {notifications.length > 0 ? notifications.map(n => (
                  <div key={n.id} className={`p-3 text-sm border-b border-border last:border-0 rounded-md ${n.read_at ? 'opacity-60' : 'bg-primary/5'} relative group`}>
                    <p className="font-medium text-ink">{n.title}</p>
                    <p className="text-muted text-xs mt-1">{n.message}</p>
                    {!n.read_at && (
                      <button 
                        onClick={() => handleMarkRead(n.id)}
                        className="absolute right-2 top-2 hidden group-hover:block text-xs text-primary bg-surface rounded px-1.5"
                      >
                        Mark read
                      </button>
                    )}
                  </div>
                )) : (
                  <p className="p-4 text-center text-sm text-muted">No notifications.</p>
                )}
              </div>
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
