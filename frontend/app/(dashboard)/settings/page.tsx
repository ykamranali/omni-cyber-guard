"use client";

import { useEffect, useState } from "react";
import { useAuthStore } from "@/store/auth";
import { Save, CheckCircle2, Paintbrush, Bell, Shield, Loader2, Send } from "lucide-react";
import { cn } from "@/lib/utils";
import { Topbar } from "@/components/layout/topbar";

export default function SettingsPage() {
  const token = useAuthStore((s) => s.accessToken);
  const [activeTab, setActiveTab] = useState<"branding" | "notifications" | "security">("branding");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [success, setSuccess] = useState(false);
  const [testingWebhook, setTestingWebhook] = useState(false);
  
  const [formData, setFormData] = useState({
    primary_color: "",
    secondary_color: "",
    footer_text: "",
    slack_webhook_url: "",
    teams_webhook_url: "",
    sso_provider: "none",
    sso_metadata_url: ""
  });

  useEffect(() => {
    fetch("http://localhost:8000/api/v1/organizations/current", {
      headers: { Authorization: `Bearer ${token}` }
    })
      .then(res => res.json())
      .then(data => {
        setFormData({
          primary_color: data.primary_color || "#0EA5E9",
          secondary_color: data.secondary_color || "#7C3AED",
          footer_text: data.footer_text || "",
          slack_webhook_url: data.slack_webhook_url || "",
          teams_webhook_url: data.teams_webhook_url || "",
          sso_provider: data.sso_provider || "none",
          sso_metadata_url: data.sso_metadata_url || ""
        });
        setLoading(false);
      });
  }, [token]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setSuccess(false);

    try {
      // Patch Branding
      if (activeTab === "branding") {
        await fetch("http://localhost:8000/api/v1/organizations/current/branding", {
          method: "PATCH",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
          body: JSON.stringify({
            primary_color: formData.primary_color,
            secondary_color: formData.secondary_color,
            footer_text: formData.footer_text
          })
        });
      } else {
        // Patch Settings
        await fetch("http://localhost:8000/api/v1/organizations/current/settings", {
          method: "PATCH",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
          body: JSON.stringify({
            slack_webhook_url: formData.slack_webhook_url || null,
            teams_webhook_url: formData.teams_webhook_url || null,
            sso_provider: formData.sso_provider,
            sso_metadata_url: formData.sso_metadata_url || null
          })
        });
      }
      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);
    } finally {
      setSaving(false);
    }
  };

  const handleTestWebhook = async () => {
    setTestingWebhook(true);
    try {
      const res = await fetch("http://localhost:8000/api/v1/organizations/current/webhooks/test", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        alert("Test alert dispatched successfully!");
      } else {
        const error = await res.json();
        alert(`Failed to send test alert: ${error.detail}`);
      }
    } catch (e) {
      alert("Network error sending test alert.");
    } finally {
      setTestingWebhook(false);
    }
  };

  if (loading) {
    return (
      <div className="flex flex-1 h-full items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent shadow-neon" />
      </div>
    );
  }

  return (
    <>
      <Topbar title="Organization Settings" />
      <div className="flex-1 overflow-y-auto p-8 bg-background">
        <div className="mx-auto max-w-5xl space-y-8">
          <div>
            <h1 className="text-2xl font-bold text-ink neon-text">Enterprise Configuration</h1>
            <p className="text-sm text-muted mt-1">Manage your organization&apos;s preferences, branding, and security configurations.</p>
          </div>

          <div className="grid gap-8 md:grid-cols-4">
            {/* Sidebar Tabs */}
            <div className="space-y-2">
              <button
                onClick={() => setActiveTab("branding")}
                className={cn(
                  "w-full flex items-center gap-3 rounded-xl px-4 py-3 text-sm font-bold tracking-wider uppercase transition-all",
                  activeTab === "branding" ? "bg-primary/10 text-primary border border-primary/30 shadow-neon" : "text-muted hover:bg-surface-hover hover:text-ink"
                )}
              >
                <Paintbrush className="h-4 w-4" /> Branding
              </button>
              <button
                onClick={() => setActiveTab("notifications")}
                className={cn(
                  "w-full flex items-center gap-3 rounded-xl px-4 py-3 text-sm font-bold tracking-wider uppercase transition-all",
                  activeTab === "notifications" ? "bg-primary/10 text-primary border border-primary/30 shadow-neon" : "text-muted hover:bg-surface-hover hover:text-ink"
                )}
              >
                <Bell className="h-4 w-4" /> Notifications
              </button>
              <button
                onClick={() => setActiveTab("security")}
                className={cn(
                  "w-full flex items-center gap-3 rounded-xl px-4 py-3 text-sm font-bold tracking-wider uppercase transition-all",
                  activeTab === "security" ? "bg-primary/10 text-primary border border-primary/30 shadow-neon" : "text-muted hover:bg-surface-hover hover:text-ink"
                )}
              >
                <Shield className="h-4 w-4" /> Security (SSO)
              </button>
            </div>

            {/* Content Area */}
            <div className="md:col-span-3">
              <div className="rounded-2xl border border-border/50 bg-surface/50 backdrop-blur-md shadow-glass overflow-hidden">
                <form onSubmit={handleSubmit}>
                  
                  {/* BRANDING TAB */}
                  {activeTab === "branding" && (
                    <>
                      <div className="border-b border-border/50 p-6 bg-surface-hover/30">
                        <h2 className="text-lg font-bold text-ink">White-label Branding</h2>
                        <p className="text-sm text-muted mt-1">Customize the platform to match your corporate identity.</p>
                      </div>
                      <div className="p-6 space-y-6">
                        <div className="grid gap-6 sm:grid-cols-2">
                          <div className="space-y-2">
                            <label className="text-xs font-bold uppercase tracking-widest text-muted">Primary Color</label>
                            <div className="flex gap-3">
                              <input
                                type="color"
                                value={formData.primary_color}
                                onChange={e => setFormData({ ...formData, primary_color: e.target.value })}
                                className="h-10 w-12 rounded-lg border border-border/50 cursor-pointer bg-background"
                              />
                              <input
                                type="text"
                                value={formData.primary_color}
                                onChange={e => setFormData({ ...formData, primary_color: e.target.value })}
                                className="flex-1 rounded-lg border border-border/50 bg-background px-3 text-sm text-ink focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/50"
                              />
                            </div>
                          </div>
                          <div className="space-y-2">
                            <label className="text-xs font-bold uppercase tracking-widest text-muted">Secondary Color</label>
                            <div className="flex gap-3">
                              <input
                                type="color"
                                value={formData.secondary_color}
                                onChange={e => setFormData({ ...formData, secondary_color: e.target.value })}
                                className="h-10 w-12 rounded-lg border border-border/50 cursor-pointer bg-background"
                              />
                              <input
                                type="text"
                                value={formData.secondary_color}
                                onChange={e => setFormData({ ...formData, secondary_color: e.target.value })}
                                className="flex-1 rounded-lg border border-border/50 bg-background px-3 text-sm text-ink focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/50"
                              />
                            </div>
                          </div>
                        </div>

                        <div className="space-y-2">
                          <label className="text-xs font-bold uppercase tracking-widest text-muted">Footer Text</label>
                          <input
                            type="text"
                            value={formData.footer_text}
                            onChange={e => setFormData({ ...formData, footer_text: e.target.value })}
                            placeholder="Powered by Omni Digital Solution"
                            className="w-full rounded-lg border border-border/50 bg-background px-3 py-2.5 text-sm text-ink focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/50"
                          />
                        </div>
                      </div>
                    </>
                  )}

                  {/* NOTIFICATIONS TAB */}
                  {activeTab === "notifications" && (
                    <>
                      <div className="border-b border-border/50 p-6 bg-surface-hover/30 flex justify-between items-center">
                        <div>
                          <h2 className="text-lg font-bold text-ink">Alerting Webhooks</h2>
                          <p className="text-sm text-muted mt-1">Configure external services for real-time security alerts.</p>
                        </div>
                        <button
                          type="button"
                          onClick={handleTestWebhook}
                          disabled={testingWebhook || (!formData.slack_webhook_url && !formData.teams_webhook_url)}
                          className="flex items-center gap-2 rounded-lg bg-surface-hover border border-border/50 px-3 py-1.5 text-xs font-bold uppercase tracking-wider text-ink transition-colors hover:bg-primary/10 hover:text-primary hover:border-primary/50 disabled:opacity-50"
                        >
                          {testingWebhook ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
                          Test Alert
                        </button>
                      </div>
                      <div className="p-6 space-y-6">
                        <div className="space-y-2">
                          <label className="text-xs font-bold uppercase tracking-widest text-muted">Slack Webhook URL</label>
                          <input
                            type="url"
                            value={formData.slack_webhook_url}
                            onChange={e => setFormData({ ...formData, slack_webhook_url: e.target.value })}
                            placeholder="https://hooks.slack.com/services/..."
                            className="w-full rounded-lg border border-border/50 bg-background px-3 py-2.5 text-sm text-ink focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/50 font-mono"
                          />
                          <p className="text-xs text-muted/70">Incoming webhook URL for Slack channel notifications.</p>
                        </div>
                        <div className="space-y-2">
                          <label className="text-xs font-bold uppercase tracking-widest text-muted">MS Teams Webhook URL</label>
                          <input
                            type="url"
                            value={formData.teams_webhook_url}
                            onChange={e => setFormData({ ...formData, teams_webhook_url: e.target.value })}
                            placeholder="https://yourtenant.webhook.office.com/webhookb2/..."
                            className="w-full rounded-lg border border-border/50 bg-background px-3 py-2.5 text-sm text-ink focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/50 font-mono"
                          />
                          <p className="text-xs text-muted/70">Incoming webhook URL for Microsoft Teams.</p>
                        </div>
                      </div>
                    </>
                  )}

                  {/* SECURITY TAB */}
                  {activeTab === "security" && (
                    <>
                      <div className="border-b border-border/50 p-6 bg-surface-hover/30">
                        <h2 className="text-lg font-bold text-ink">Single Sign-On (SSO)</h2>
                        <p className="text-sm text-muted mt-1">Configure enterprise identity providers (SAML/OIDC).</p>
                      </div>
                      <div className="p-6 space-y-6">
                        <div className="space-y-2">
                          <label className="text-xs font-bold uppercase tracking-widest text-muted">Identity Provider</label>
                          <select
                            value={formData.sso_provider}
                            onChange={e => setFormData({ ...formData, sso_provider: e.target.value })}
                            className="w-full rounded-lg border border-border/50 bg-background px-3 py-2.5 text-sm text-ink focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/50"
                          >
                            <option value="none">Disabled (Local Auth Only)</option>
                            <option value="okta">Okta</option>
                            <option value="azure">Azure Active Directory</option>
                            <option value="auth0">Auth0</option>
                            <option value="generic_saml">Generic SAML 2.0</option>
                          </select>
                        </div>
                        
                        {formData.sso_provider !== "none" && (
                          <div className="space-y-2 animate-in fade-in slide-in-from-top-2 duration-300">
                            <label className="text-xs font-bold uppercase tracking-widest text-muted">Metadata URL</label>
                            <input
                              type="url"
                              value={formData.sso_metadata_url}
                              onChange={e => setFormData({ ...formData, sso_metadata_url: e.target.value })}
                              placeholder="https://idp.example.com/metadata.xml"
                              className="w-full rounded-lg border border-border/50 bg-background px-3 py-2.5 text-sm text-ink focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/50 font-mono"
                            />
                            <p className="text-xs text-muted/70">The URL to auto-fetch your IdP's metadata XML.</p>
                          </div>
                        )}
                      </div>
                    </>
                  )}

                  {/* Submit Button Area */}
                  <div className="border-t border-border/50 bg-surface p-6 flex items-center justify-between">
                    {success ? (
                      <span className="flex items-center gap-2 text-sm font-bold text-green-500 animate-in fade-in duration-300">
                        <CheckCircle2 className="h-5 w-5 drop-shadow-[0_0_8px_rgba(34,197,94,0.5)]" /> Saved successfully!
                      </span>
                    ) : <span />}
                    <button
                      type="submit"
                      disabled={saving}
                      className="flex items-center gap-2 rounded-xl bg-primary px-6 py-2.5 text-sm font-bold text-primary-foreground transition-all hover:bg-primary-hover hover:shadow-neon disabled:opacity-50"
                    >
                      {saving ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <Save className="h-4 w-4" />
                      )}
                      Save Configuration
                    </button>
                  </div>
                  
                </form>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
