"use client";

import { useEffect, useState } from "react";
import { useAuthStore } from "@/store/auth";
import { Settings, Save, CheckCircle2, Paintbrush, Bell, Shield } from "lucide-react";
import { cn } from "@/lib/utils";

export default function SettingsPage() {
  const token = useAuthStore((s) => s.accessToken);
  const [org, setOrg] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [success, setSuccess] = useState(false);
  
  const [formData, setFormData] = useState({
    primary_color: "",
    secondary_color: "",
    footer_text: ""
  });

  useEffect(() => {
    fetch("http://localhost:8000/api/v1/organizations/current", {
      headers: { Authorization: `Bearer ${token}` }
    })
      .then(res => res.json())
      .then(data => {
        setOrg(data);
        setFormData({
          primary_color: data.primary_color || "#0EA5E9",
          secondary_color: data.secondary_color || "#7C3AED",
          footer_text: data.footer_text || ""
        });
        setLoading(false);
      });
  }, [token]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setSuccess(false);

    try {
      const res = await fetch("http://localhost:8000/api/v1/organizations/current/branding", {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify(formData)
      });
      if (res.ok) {
        setSuccess(true);
        setTimeout(() => setSuccess(false), 3000);
      }
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6 pb-12">
      <div>
        <h1 className="text-2xl font-bold text-ink">Organization Settings</h1>
        <p className="text-sm text-muted">Manage your organization&apos;s preferences, branding, and security configurations.</p>
      </div>

      <div className="grid gap-6 md:grid-cols-4">
        <div className="space-y-1">
          <div className="rounded-lg bg-surface-hover px-3 py-2 text-sm font-medium text-ink flex items-center gap-2">
            <Paintbrush className="h-4 w-4 text-primary" /> Branding
          </div>
          <div className="rounded-lg px-3 py-2 text-sm font-medium text-muted hover:bg-surface-hover/50 cursor-pointer flex items-center gap-2">
            <Bell className="h-4 w-4" /> Notifications
          </div>
          <div className="rounded-lg px-3 py-2 text-sm font-medium text-muted hover:bg-surface-hover/50 cursor-pointer flex items-center gap-2">
            <Shield className="h-4 w-4" /> Security
          </div>
        </div>

        <div className="md:col-span-3 space-y-6">
          <div className="rounded-xl border border-border bg-surface">
            <div className="border-b border-border p-5">
              <h2 className="text-lg font-semibold text-ink">White-label Branding</h2>
              <p className="text-sm text-muted mt-1">Customize the platform to match your corporate identity.</p>
            </div>
            <form onSubmit={handleSubmit} className="p-5 space-y-5">
              <div className="grid gap-5 sm:grid-cols-2">
                <div className="space-y-2">
                  <label className="text-sm font-medium text-ink">Primary Color</label>
                  <div className="flex gap-3">
                    <input
                      type="color"
                      value={formData.primary_color}
                      onChange={e => setFormData({ ...formData, primary_color: e.target.value })}
                      className="h-10 w-12 rounded border border-border cursor-pointer bg-surface"
                    />
                    <input
                      type="text"
                      value={formData.primary_color}
                      onChange={e => setFormData({ ...formData, primary_color: e.target.value })}
                      className="flex-1 rounded-lg border border-border bg-surface-hover px-3 text-sm text-ink focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                    />
                  </div>
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium text-ink">Secondary Color</label>
                  <div className="flex gap-3">
                    <input
                      type="color"
                      value={formData.secondary_color}
                      onChange={e => setFormData({ ...formData, secondary_color: e.target.value })}
                      className="h-10 w-12 rounded border border-border cursor-pointer bg-surface"
                    />
                    <input
                      type="text"
                      value={formData.secondary_color}
                      onChange={e => setFormData({ ...formData, secondary_color: e.target.value })}
                      className="flex-1 rounded-lg border border-border bg-surface-hover px-3 text-sm text-ink focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                    />
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium text-ink">Footer Text</label>
                <input
                  type="text"
                  value={formData.footer_text}
                  onChange={e => setFormData({ ...formData, footer_text: e.target.value })}
                  placeholder="Powered by Omni Digital Solution"
                  className="w-full rounded-lg border border-border bg-surface-hover px-3 py-2 text-sm text-ink focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>

              <div className="flex items-center gap-4 pt-4">
                <button
                  type="submit"
                  disabled={saving}
                  className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary/90 disabled:opacity-50"
                >
                  {saving ? (
                    <div className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                  ) : (
                    <Save className="h-4 w-4" />
                  )}
                  Save Changes
                </button>
                {success && (
                  <span className="flex items-center gap-2 text-sm text-green-500">
                    <CheckCircle2 className="h-4 w-4" /> Saved successfully!
                  </span>
                )}
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}
