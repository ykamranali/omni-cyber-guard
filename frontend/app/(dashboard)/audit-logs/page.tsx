"use client";

import { useEffect, useState } from "react";
import { useAuthStore } from "@/store/auth";
import { ScrollText, Search, User, Monitor, Clock } from "lucide-react";
import { format } from "date-fns";

interface AuditLog {
  id: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  ip_address: string | null;
  created_at: string;
  actor_user_id: string | null;
  metadata: any;
}

export default function AuditLogsPage() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const token = useAuthStore((s) => s.accessToken);

  useEffect(() => {
    fetch("http://localhost:8000/api/v1/audit-logs", {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.json())
      .then((data) => {
        setLogs(data.items);
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

  const filteredLogs = logs.filter((l) => 
    l.action.toLowerCase().includes(search.toLowerCase()) || 
    l.resource_type.toLowerCase().includes(search.toLowerCase()) ||
    l.ip_address?.includes(search)
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-ink">Audit Logs</h1>
        <p className="text-sm text-muted">Track historical actions and events across your organization.</p>
      </div>

      <div className="rounded-xl border border-border bg-surface">
        <div className="border-b border-border p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ScrollText className="h-5 w-5 text-primary" />
              <h2 className="text-lg font-semibold text-ink">Event History</h2>
            </div>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
              <input
                type="text"
                placeholder="Search events..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-64 rounded-lg border border-border bg-surface-hover pl-9 pr-4 py-2 text-sm text-ink placeholder:text-muted focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-ink">
            <thead className="bg-surface-hover/50 text-xs uppercase text-muted">
              <tr>
                <th className="px-6 py-4 font-medium">Timestamp</th>
                <th className="px-6 py-4 font-medium">Action</th>
                <th className="px-6 py-4 font-medium">Resource</th>
                <th className="px-6 py-4 font-medium">Actor</th>
                <th className="px-6 py-4 font-medium">IP Address</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filteredLogs.map((log) => (
                <tr key={log.id} className="hover:bg-surface-hover/30">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center gap-2 text-muted">
                      <Clock className="h-3 w-3" />
                      {format(new Date(log.created_at), "MMM d, yyyy HH:mm:ss")}
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className="rounded bg-primary/10 px-2 py-1 text-xs font-medium text-primary">
                      {log.action}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <div className="font-medium">{log.resource_type}</div>
                    <div className="font-mono text-xs text-muted">{log.resource_id}</div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <User className="h-4 w-4 text-muted" />
                      <span className="font-mono text-xs text-muted truncate max-w-[120px]">
                        {log.actor_user_id || "System"}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <Monitor className="h-4 w-4 text-muted" />
                      <span className="text-muted">{log.ip_address || "N/A"}</span>
                    </div>
                  </td>
                </tr>
              ))}
              {filteredLogs.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-6 py-8 text-center text-muted">
                    No logs found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
