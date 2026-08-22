"use client";

import { useEffect, useState, useCallback } from "react";
import { useAuthStore } from "@/store/auth";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loader2, Users, ShieldAlert, Key, AlertTriangle, RefreshCw } from "lucide-react";
import { format } from "date-fns";
import { Button } from "@/components/ui/button";

export default function IdentityPage() {
  const [identities, setIdentities] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isSyncing, setIsSyncing] = useState(false);

  const runSync = async (provider: string) => {
    setIsSyncing(true);
    try {
      const token = useAuthStore.getState().accessToken;
      await fetch("/api/v1/identity/scan", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ provider }),
      });
      alert(`Sync started for ${provider}. Waiting for background job to finish.`);
      setTimeout(fetchIdentities, 3000);
    } catch (err) {
      console.error(err);
      alert("Failed to start identity sync.");
    } finally {
      setIsSyncing(false);
    }
  };

  const fetchIdentities = useCallback(async () => {
    try {
      const token = useAuthStore.getState().accessToken;
      if (!token) return;

      const res = await fetch("/api/v1/identity/", {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) throw new Error("Failed to fetch identities");
      const data = await res.json();
      setIdentities(data);
    } catch (err: any) {
      console.error(err);
      setError("Could not load identity data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchIdentities();
  }, [fetchIdentities]);

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

  const adminCount = identities.filter(i => i.privilege_level.toUpperCase() === "ADMIN").length;
  const noMfaCount = identities.filter(i => !i.mfa_enabled).length;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Identity & Access (ITDR)</h2>
          <p className="text-muted-foreground">
            Monitor corporate identities, privileges, and MFA posture synced from Entra ID / Okta.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => runSync("Entra ID")} disabled={isSyncing}>
            {isSyncing ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <RefreshCw className="h-4 w-4 mr-2" />}
            Sync Entra ID
          </Button>
          <Button variant="outline" onClick={() => runSync("Okta")} disabled={isSyncing}>
            {isSyncing ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <RefreshCw className="h-4 w-4 mr-2" />}
            Sync Okta
          </Button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Identities</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{identities.length}</div>
            <p className="text-xs text-muted-foreground">Synched from IdPs</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Admin Accounts</CardTitle>
            <Key className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{adminCount}</div>
            <p className="text-xs text-muted-foreground">Highly privileged accounts</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Missing MFA</CardTitle>
            <ShieldAlert className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-500">{noMfaCount}</div>
            <p className="text-xs text-muted-foreground">Accounts lacking MFA</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Identity Inventory</CardTitle>
          <CardDescription>
            List of all synced user accounts and their security posture.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-muted/50 text-left">
                  <th className="p-4 font-medium">User</th>
                  <th className="p-4 font-medium">Provider</th>
                  <th className="p-4 font-medium">Status</th>
                  <th className="p-4 font-medium">MFA Status</th>
                  <th className="p-4 font-medium">Privilege</th>
                  <th className="p-4 font-medium">Last Login</th>
                </tr>
              </thead>
              <tbody>
                {identities.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="p-4 text-center text-muted-foreground">
                      No identities discovered yet.
                    </td>
                  </tr>
                ) : (
                  identities.map((profile) => (
                    <tr key={profile.id} className="border-b last:border-0 hover:bg-muted/30">
                      <td className="p-4">
                        <div className="flex flex-col">
                          <span className="font-medium">{profile.full_name || profile.email.split("@")[0]}</span>
                          <span className="text-xs text-muted-foreground">{profile.email}</span>
                        </div>
                      </td>
                      <td className="p-4 text-muted-foreground">{profile.provider}</td>
                      <td className="p-4">
                        <Badge label={profile.is_active ? "active" : "inactive"} />
                      </td>
                      <td className="p-4">
                        {profile.mfa_enabled ? (
                          <Badge label="active" />
                        ) : (
                          <Badge label="critical" />
                        )}
                      </td>
                      <td className="p-4">
                        {profile.privilege_level.toUpperCase() === "ADMIN" ? (
                          <Badge label="high" />
                        ) : (
                          <span className="text-muted-foreground">User</span>
                        )}
                      </td>
                      <td className="p-4 text-muted-foreground">
                        {profile.last_login ? format(new Date(profile.last_login), "PP p") : "Never"}
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
