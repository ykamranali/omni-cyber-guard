"use client";

import { useEffect, useState, useCallback } from "react";
import { useAuthStore } from "@/store/auth";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loader2, Cloud, AlertTriangle, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function CloudAssetsPage() {
  const [resources, setResources] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isSyncing, setIsSyncing] = useState(false);

  const runSync = async (provider: string) => {
    setIsSyncing(true);
    try {
      const token = useAuthStore.getState().accessToken;
      await fetch("/api/v1/cloud/scan", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ provider }),
      });
      alert(`Sync started for ${provider}. Waiting for background job to finish.`);
      setTimeout(fetchResources, 3000);
    } catch (err) {
      console.error(err);
      alert("Failed to start cloud sync.");
    } finally {
      setIsSyncing(false);
    }
  };

  const fetchResources = useCallback(async () => {
    try {
      const token = useAuthStore.getState().accessToken;
      if (!token) return;

      const res = await fetch("/api/v1/cloud/", {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) throw new Error("Failed to fetch cloud resources");
      const data = await res.json();
      setResources(data);
    } catch (err: any) {
      console.error(err);
      setError("Could not load cloud resources data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchResources();
    const interval = setInterval(fetchResources, 5000);
    return () => clearInterval(interval);
  }, [fetchResources]);

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex h-64 items-center justify-center text-red-500">
        <AlertTriangle className="h-6 w-6 mr-2" />
        {error}
      </div>
    );
  }

  const awsCount = resources.filter(r => r.provider.toLowerCase() === "aws").length;
  const azureCount = resources.filter(r => r.provider.toLowerCase() === "azure").length;
  const gcpCount = resources.filter(r => r.provider.toLowerCase() === "gcp").length;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Cloud Assets (CSPM)</h2>
          <p className="text-muted-foreground">
            Inventory and compliance status for your AWS, Azure, and GCP resources.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => runSync("AWS")} disabled={isSyncing}>
            {isSyncing ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <RefreshCw className="h-4 w-4 mr-2" />}
            Sync AWS
          </Button>
          <Button variant="outline" onClick={() => runSync("Azure")} disabled={isSyncing}>
            {isSyncing ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <RefreshCw className="h-4 w-4 mr-2" />}
            Sync Azure
          </Button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Resources</CardTitle>
            <Cloud className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{resources.length}</div>
            <p className="text-xs text-muted-foreground">Across all providers</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">AWS Assets</CardTitle>
            <Cloud className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{awsCount}</div>
            <p className="text-xs text-muted-foreground">Discovered instances</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Azure Assets</CardTitle>
            <Cloud className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{azureCount}</div>
            <p className="text-xs text-muted-foreground">Discovered instances</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">GCP Assets</CardTitle>
            <Cloud className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{gcpCount}</div>
            <p className="text-xs text-muted-foreground">Discovered instances</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Cloud Resource Inventory</CardTitle>
          <CardDescription>
            A comprehensive list of all discovered cloud assets.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-muted/50 text-left">
                  <th className="p-4 font-medium">Name</th>
                  <th className="p-4 font-medium">Provider</th>
                  <th className="p-4 font-medium">Type</th>
                  <th className="p-4 font-medium">Region</th>
                  <th className="p-4 font-medium">Status</th>
                  <th className="p-4 font-medium">Compliance</th>
                </tr>
              </thead>
              <tbody>
                {resources.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="p-4 text-center text-muted-foreground">
                      No cloud resources discovered yet.
                    </td>
                  </tr>
                ) : (
                  resources.map((resource) => (
                    <tr key={resource.id} className="border-b last:border-0 hover:bg-muted/30">
                      <td className="p-4 font-medium">{resource.name}</td>
                      <td className="p-4 font-semibold text-muted-foreground uppercase">{resource.provider}</td>
                      <td className="p-4 text-muted-foreground">{resource.resource_type}</td>
                      <td className="p-4 text-muted-foreground">{resource.region}</td>
                      <td className="p-4">
                        <Badge label={resource.status} />
                      </td>
                      <td className="p-4">
                        <Badge label={resource.compliance_status} />
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
