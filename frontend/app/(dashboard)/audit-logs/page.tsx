"use client";

import { useEffect, useState } from "react";
import { useAuthStore } from "@/store/auth";
import { api } from "@/lib/api";
import { ScrollText, Search, User, Monitor, Clock, ChevronRight } from "lucide-react";
import { format } from "date-fns";
import { motion } from "framer-motion";

interface AuditLog {
  id: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  ip_address: string | null;
  created_at: string;
  actor_user_id: string | null;
  actor_email: string | null;
  metadata: any;
}

export default function AuditLogsPage() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const token = useAuthStore((s) => s.accessToken);

  useEffect(() => {
    api
      .get<{ items: AuditLog[] }>("/audit-logs")
      .then((data) => setLogs(data.items ?? []))
      .catch((error) => console.error("Failed to load audit logs", error))
      .finally(() => setLoading(false));
  }, [token]);

  const filteredLogs = logs.filter((l) => 
    l.action.toLowerCase().includes(search.toLowerCase()) || 
    l.resource_type.toLowerCase().includes(search.toLowerCase()) ||
    l.ip_address?.includes(search) ||
    l.actor_email?.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="flex h-full flex-col gap-6 p-6 max-w-[1600px] mx-auto w-full">
      <motion.div 
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-center gap-4 border-b border-border/50 pb-6"
      >
        <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10 border border-primary/20 shadow-neon">
          <ScrollText className="h-6 w-6 text-primary" />
        </div>
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-ink neon-text">Audit Logs</h1>
          <p className="text-muted mt-1">Immutable ledger of historical actions and system events.</p>
        </div>
      </motion.div>

      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="rounded-2xl glass-panel overflow-hidden flex flex-col"
      >
        <div className="border-b border-border/50 bg-surface/50 p-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <div className="h-2 w-2 rounded-full bg-primary animate-pulse-glow" />
              <h2 className="text-lg font-semibold text-ink tracking-wide">Event Chronicle</h2>
            </div>
            <div className="relative w-full sm:w-auto">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
              <input
                type="text"
                placeholder="Search events, IPs, or actors..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full sm:w-80 rounded-xl border border-border/50 bg-surface/50 pl-10 pr-4 py-2.5 text-sm text-ink placeholder:text-muted focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/50 transition-all shadow-[inset_0_2px_4px_rgba(0,0,0,0.1)]"
              />
            </div>
          </div>
        </div>

        <div className="overflow-x-auto">
          {loading ? (
             <div className="flex h-64 items-center justify-center">
               <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent shadow-[0_0_15px_currentColor] text-primary" />
             </div>
          ) : (
            <table className="w-full text-left text-sm text-ink">
              <thead className="bg-surface-hover/30 text-[10px] tracking-widest uppercase text-muted border-b border-border/50">
                <tr>
                  <th className="px-6 py-4 font-bold">Timestamp</th>
                  <th className="px-6 py-4 font-bold">Action</th>
                  <th className="px-6 py-4 font-bold">Resource</th>
                  <th className="px-6 py-4 font-bold">Actor</th>
                  <th className="px-6 py-4 font-bold">IP Address</th>
                  <th className="px-6 py-4 font-bold text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/30">
                {filteredLogs.map((log, i) => (
                  <motion.tr 
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.05 }}
                    key={log.id} 
                    className="hover:bg-surface-hover/40 transition-colors group cursor-pointer"
                  >
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center gap-2 text-muted font-mono text-xs">
                        <Clock className="h-3.5 w-3.5 text-primary/70" />
                        {format(new Date(log.created_at), "yyyy-MM-dd HH:mm:ss")}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className="rounded-md bg-primary/10 border border-primary/20 px-2.5 py-1 text-xs font-semibold tracking-wide text-primary shadow-[0_0_10px_rgba(var(--color-primary)/0.1)]">
                        {log.action}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="font-semibold text-ink">{log.resource_type}</div>
                      <div className="font-mono text-[10px] text-muted mt-0.5">{log.resource_id}</div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <div className="bg-surface-hover p-1.5 rounded-md border border-border/50">
                          <User className="h-3.5 w-3.5 text-muted" />
                        </div>
                        <span className="text-sm truncate max-w-[200px]" title={log.actor_user_id || ""}>
                          {log.actor_email || log.actor_user_id || "System"}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <Monitor className="h-3.5 w-3.5 text-muted" />
                        <span className="text-muted font-mono text-xs bg-surface-hover px-2 py-0.5 rounded border border-border/30">{log.ip_address || "Internal"}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <ChevronRight className="h-4 w-4 text-muted inline-block group-hover:text-primary transition-colors" />
                    </td>
                  </motion.tr>
                ))}
                {filteredLogs.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-6 py-12 text-center">
                      <div className="inline-flex flex-col items-center justify-center p-6 bg-surface-hover/30 rounded-2xl border border-dashed border-border">
                        <Search className="h-8 w-8 text-muted mb-3" />
                        <p className="text-ink font-medium">No events found matching your search.</p>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>
      </motion.div>
    </div>
  );
}

