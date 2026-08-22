"use client";

import { useEffect, useState, useCallback } from "react";
import { useAuthStore } from "@/store/auth";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loader2, ArrowRight } from "lucide-react";

export default function AttackPathsPage() {
  const [paths, setPaths] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchPaths = useCallback(async () => {
    try {
      const token = useAuthStore.getState().accessToken;
      if (!token) return;

      const res = await fetch("/api/v1/attack-paths/", {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) throw new Error("Failed to fetch attack paths");
      const data = await res.json();
      setPaths(data);
    } catch (err: any) {
      console.error(err);
      setError("Could not load attack paths");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchPaths();
  }, [fetchPaths]);

  const getSeverityBadge = (score: number) => {
    if (score >= 90) return <Badge label="critical" />;
    if (score >= 70) return <Badge label="high" />;
    if (score >= 40) return <Badge label="medium" />;
    return <Badge label="low" />;
  };

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Attack Paths</h1>
        <p className="text-muted-foreground mt-2">
          Potential paths an attacker could take to compromise critical assets, derived from the exposure graph.
        </p>
      </div>

      <div className="grid gap-6">
        {loading ? (
          <div className="flex justify-center p-8">
            <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
          </div>
        ) : paths.length === 0 ? (
          <Card>
            <CardContent className="flex flex-col items-center justify-center p-12 text-center">
              <div className="rounded-full bg-muted p-4 mb-4">
                <ArrowRight className="h-8 w-8 text-muted-foreground opacity-50" />
              </div>
              <p className="text-lg font-medium">No Attack Paths Identified</p>
              <p className="text-sm text-muted-foreground max-w-sm mt-2">
                The graph engine has not found any exploitable paths from external sources to internal assets.
              </p>
            </CardContent>
          </Card>
        ) : (
          paths.map((path, idx) => (
            <Card key={path.id}>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-lg">Path #{idx + 1}</CardTitle>
                    <CardDescription className="mt-1">
                      From {path.source_node_type} to {path.target_node_type}
                    </CardDescription>
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="text-right">
                      <div className="text-2xl font-bold">{Math.round(path.risk_score)}</div>
                      <div className="text-xs text-muted-foreground uppercase">Risk Score</div>
                    </div>
                    {getSeverityBadge(path.risk_score)}
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="w-full whitespace-nowrap pb-4 overflow-x-auto">
                  <div className="flex items-center gap-3 py-4 min-w-max">
                    {path.path_nodes.map((node: any, nIdx: number) => (
                      <div key={nIdx} className="flex items-center gap-3">
                        <div className="flex flex-col border rounded-md px-4 py-3 bg-muted/30">
                          <span className="text-xs font-semibold text-muted-foreground uppercase">
                            {node.type}
                          </span>
                          <span className="text-sm font-medium mt-1">{node.name}</span>
                          {node.severity && (
                            <span className="text-xs mt-1 text-red-500 font-medium">
                              {node.severity}
                            </span>
                          )}
                        </div>
                        {nIdx < path.path_nodes.length - 1 && (
                          <div className="text-muted-foreground">
                            <ArrowRight className="h-5 w-5" />
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>
    </div>
  );
}
