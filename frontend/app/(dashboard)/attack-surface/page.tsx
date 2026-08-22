"use client";

import { useEffect, useState, useCallback } from "react";
import { useAuthStore } from "@/store/auth";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loader2, Globe, Shield, AlertTriangle, Radar, Plus } from "lucide-react";
import { format } from "date-fns";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

export default function AttackSurfacePage() {
  const [domains, setDomains] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isDiscovering, setIsDiscovering] = useState(false);

  const runDiscovery = async (domain: string) => {
    setIsDiscovering(true);
    try {
      const token = useAuthStore.getState().accessToken;
      await fetch("/api/v1/attack-surface/scan", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      });
      alert(`Discovery started for ${domain}. It may take a minute to appear.`);
      setTimeout(fetchDomains, 3000);
    } catch (err) {
      console.error(err);
      alert("Failed to start discovery.");
    } finally {
      setIsDiscovering(false);
    }
  };

  const fetchDomains = useCallback(async () => {
    try {
      const token = useAuthStore.getState().accessToken;
      if (!token) return;

      const res = await fetch("/api/v1/attack-surface/", {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) throw new Error("Failed to fetch attack surface data");
      const data = await res.json();
      setDomains(data);
    } catch (err: any) {
      console.error(err);
      setError("Could not load external attack surface data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDomains();
  }, [fetchDomains]);

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

  const expiringCerts = domains.filter((d) => {
    if (!d.cert_valid_to) return false;
    const daysUntilExpiry = (new Date(d.cert_valid_to).getTime() - new Date().getTime()) / (1000 * 3600 * 24);
    return daysUntilExpiry < 30;
  }).length;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">External Attack Surface</h2>
          <p className="text-muted-foreground">
            Discover and monitor your internet-facing assets, domains, and certificates.
          </p>
        </div>
        <form onSubmit={(e) => {
          e.preventDefault();
          const target = (e.target as any).domain.value;
          if (target) {
            runDiscovery(target);
            (e.target as any).reset();
          }
        }} className="flex items-center gap-2">
          <Input name="domain" placeholder="example.com" className="w-64" required />
          <Button type="submit" disabled={isDiscovering}>
            {isDiscovering ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Radar className="h-4 w-4 mr-2" />}
            Run Discovery
          </Button>
        </form>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Domains</CardTitle>
            <Globe className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{domains.length}</div>
            <p className="text-xs text-muted-foreground">Discovered via passive reconnaissance</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active IPs</CardTitle>
            <Globe className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {new Set(domains.flatMap((d) => d.ip_addresses)).size}
            </div>
            <p className="text-xs text-muted-foreground">Resolving IP addresses</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Expiring Certificates</CardTitle>
            <Shield className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-500">{expiringCerts}</div>
            <p className="text-xs text-muted-foreground">Expiring within 30 days</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Discovered Domains</CardTitle>
          <CardDescription>
            A list of all publicly discoverable domains associated with your organization.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-muted/50 text-left">
                  <th className="p-4 font-medium">Domain Name</th>
                  <th className="p-4 font-medium">IP Addresses</th>
                  <th className="p-4 font-medium">Registrar</th>
                  <th className="p-4 font-medium">Status</th>
                  <th className="p-4 font-medium">Cert Issuer</th>
                  <th className="p-4 font-medium">Cert Expiry</th>
                </tr>
              </thead>
              <tbody>
                {domains.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="p-4 text-center text-muted-foreground">
                      No domains discovered yet.
                    </td>
                  </tr>
                ) : (
                  domains.map((domain) => {
                    let certStatus = "valid";
                    if (domain.cert_valid_to) {
                      const daysUntilExpiry = (new Date(domain.cert_valid_to).getTime() - new Date().getTime()) / (1000 * 3600 * 24);
                      if (daysUntilExpiry < 0) certStatus = "expired";
                      else if (daysUntilExpiry < 30) certStatus = "expiring";
                    }

                    return (
                      <tr key={domain.id} className="border-b last:border-0 hover:bg-muted/30">
                        <td className="p-4 font-medium">{domain.domain_name}</td>
                        <td className="p-4 text-muted-foreground">
                          {domain.ip_addresses.join(", ") || "-"}
                        </td>
                        <td className="p-4 text-muted-foreground">{domain.registrar || "-"}</td>
                        <td className="p-4">
                          <Badge label={domain.is_active ? "active" : "inactive"} />
                        </td>
                        <td className="p-4 text-muted-foreground">{domain.cert_issuer || "-"}</td>
                        <td className="p-4">
                          {domain.cert_valid_to ? (
                            <span className={certStatus === "expired" || certStatus === "expiring" ? "text-red-500 font-medium" : ""}>
                              {format(new Date(domain.cert_valid_to), "PP")}
                            </span>
                          ) : (
                            "-"
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
