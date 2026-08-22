"use client";

import { useEffect, useState } from "react";
import { 
  ScrollText, Search, Filter, ShieldAlert,
  User, Database, Server, RefreshCw
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

interface AuditLog {
  id: string;
  action: string;
  resource_type: string;
  resource_id: string;
  ip_address: string;
  created_at: string;
  actor_user_id: string | null;
  actor_email: string | null;
  metadata: any;
}

interface AuditLogResponse {
  items: AuditLog[];
  total: number;
  skip: number;
  limit: number;
}

export default function AuditLogsPage() {
  const [data, setData] = useState<AuditLogResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");

  useEffect(() => {
    fetchLogs();
  }, []);

  const fetchLogs = async () => {
    try {
      const res = await api.get<AuditLogResponse>("/audit-logs");
      setData(res);
    } catch (error) {
      console.error("Failed to load audit logs:", error);
    } finally {
      setLoading(false);
    }
  };

  const getActionColor = (action: string) => {
    if (action.includes("delete") || action.includes("remove") || action.includes("block")) return "text-rose-500 bg-rose-500/10 border-rose-500/20";
    if (action.includes("create") || action.includes("add") || action.includes("resolve")) return "text-emerald-500 bg-emerald-500/10 border-emerald-500/20";
    if (action.includes("update") || action.includes("modify")) return "text-amber-500 bg-amber-500/10 border-amber-500/20";
    return "text-blue-500 bg-blue-500/10 border-blue-500/20";
  };

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <RefreshCw className="h-8 w-8 animate-spin text-primary" />
          <p className="text-sm text-muted">Loading Audit Logs...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-ink">Audit Logs</h1>
          <p className="mt-2 text-muted">System-wide activity monitoring and compliance tracking</p>
        </div>
        <button className="flex items-center gap-2 rounded-lg border border-border bg-surface px-4 py-2 text-sm font-medium text-ink transition-all hover:bg-surface-hover">
          Export Logs
        </button>
      </div>

      <div className="rounded-xl border border-border bg-surface shadow-lg backdrop-blur-xl">
        <div className="flex items-center justify-between border-b border-border p-4">
          <div className="flex items-center gap-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
              <input
                type="text"
                placeholder="Search logs..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="h-10 w-64 rounded-lg border border-border bg-surface-hover pl-9 pr-4 text-sm text-ink placeholder:text-muted focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
            <button className="flex items-center gap-2 rounded-lg border border-border px-3 py-2 text-sm font-medium text-ink transition-colors hover:bg-surface-hover">
              <Filter className="h-4 w-4" /> Filter
            </button>
          </div>
          <div className="text-sm text-muted">
            Total Records: <span className="font-bold text-ink">{data?.total.toLocaleString() || 0}</span>
          </div>
        </div>

        {data?.items.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-center">
            <ScrollText className="mb-4 h-12 w-12 text-muted/30" />
            <p className="text-lg font-medium text-ink">No Activity Found</p>
            <p className="mt-1 text-sm text-muted">There are no audit logs recorded for your organization yet.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-surface-hover/50 text-xs uppercase tracking-wider text-muted">
                <tr>
                  <th className="px-6 py-4 font-medium">Action</th>
                  <th className="px-6 py-4 font-medium">Resource</th>
                  <th className="px-6 py-4 font-medium">Actor</th>
                  <th className="px-6 py-4 font-medium">IP Address</th>
                  <th className="px-6 py-4 font-medium">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/50">
                {data?.items.map((log) => (
                  <tr key={log.id} className="transition-colors hover:bg-surface-hover/50">
                    <td className="px-6 py-4">
                      <span className={cn("inline-flex rounded-full border px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider", getActionColor(log.action))}>
                        {log.action.replace("_", " ")}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-col gap-1">
                        <span className="font-semibold text-ink capitalize">{log.resource_type}</span>
                        <span className="font-mono text-[10px] text-muted">{log.resource_id.substring(0, 8)}...</span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        {log.actor_user_id ? (
                          <>
                            <User className="h-4 w-4 text-primary" />
                            <span className="font-medium text-ink">{log.actor_email}</span>
                          </>
                        ) : (
                          <>
                            <Server className="h-4 w-4 text-purple-500" />
                            <span className="italic text-muted">System Action</span>
                          </>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 font-mono text-xs text-muted">
                      {log.ip_address || "-"}
                    </td>
                    <td className="px-6 py-4 text-xs text-muted">
                      {new Date(log.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
