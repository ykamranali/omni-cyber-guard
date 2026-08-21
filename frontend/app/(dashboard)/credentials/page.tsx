"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Lock, Plus, RefreshCw, Trash2 } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { Topbar } from "@/components/layout/topbar";
import { Button } from "@/components/ui/button";
import { Modal } from "@/components/ui/modal";
import { api } from "@/lib/api";

interface CredentialProfile {
  id: string;
  name: string;
  description: string;
  credential_type: string;
  username: string;
  domain: string;
  last_used_at: string | null;
  rotated_at: string | null;
  created_at: string;
  secret_set: boolean;
}

const CREDENTIAL_TYPES = [
  { value: "ssh_password", label: "SSH (password)" },
  { value: "ssh_key", label: "SSH (private key)" },
  { value: "windows", label: "Windows / WinRM" },
  { value: "snmp_v2c", label: "SNMP v2c community" },
  { value: "snmp_v3", label: "SNMP v3" },
  { value: "ldap", label: "LDAP / Active Directory" },
  { value: "aws", label: "AWS" },
  { value: "azure", label: "Azure" },
  { value: "gcp", label: "Google Cloud" },
  { value: "api_token", label: "API token" },
  { value: "database", label: "Database" },
];

const SECRET_LABELS: Record<string, string> = {
  ssh_key: "Private key",
  snmp_v2c: "Community string",
  api_token: "Token",
};

const inputClass =
  "w-full rounded-md border border-border bg-surface-hover px-3 py-2 text-sm text-ink focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary";

export default function CredentialsPage() {
  const queryClient = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [rotating, setRotating] = useState<CredentialProfile | null>(null);
  const [error, setError] = useState<string | null>(null);

  const { data: credentials = [], isLoading } = useQuery({
    queryKey: ["credentials"],
    queryFn: () => api.get<CredentialProfile[]>("/credentials"),
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["credentials"] });

  const create = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post("/credentials", body),
    onSuccess: () => { invalidate(); setCreateOpen(false); setError(null); },
    onError: (err: Error) => setError(err.message),
  });

  const rotate = useMutation({
    mutationFn: ({ id, secret }: { id: string; secret: string }) =>
      api.patch(`/credentials/${id}`, { secret }),
    onSuccess: () => { invalidate(); setRotating(null); setError(null); },
    onError: (err: Error) => setError(err.message),
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/credentials/${id}`),
    onSuccess: invalidate,
  });

  return (
    <>
      <Topbar title="Credentials" />
      <main className="flex-1 space-y-6 overflow-y-auto p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-ink">Credential Vault</h1>
            <p className="text-sm text-muted">
              Credentials used for authenticated assessment. Secrets are encrypted at rest and
              never returned by the API.
            </p>
          </div>
          <Button onClick={() => { setError(null); setCreateOpen(true); }}>
            <Plus className="mr-2 h-4 w-4" /> Add credential
          </Button>
        </div>

        <div className="flex gap-3 rounded-xl border border-primary/30 bg-primary/5 p-4">
          <Lock className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
          <div className="space-y-1">
            <p className="text-sm font-semibold text-ink">Secrets cannot be read back</p>
            <p className="text-sm leading-relaxed text-muted">
              A stored secret is decrypted only by the scanner about to authenticate with it, and
              every decryption is written to the audit log with the actor and the target. There is
              no API response that carries a secret value — if you lose one, rotate it rather than
              trying to recover it.
            </p>
          </div>
        </div>

        {isLoading ? (
          <div className="rounded-xl border border-border bg-surface p-8 text-center text-muted">
            Loading credentials…
          </div>
        ) : credentials.length === 0 ? (
          <div className="rounded-xl border border-dashed border-border bg-surface p-12 text-center">
            <KeyRound className="mx-auto h-10 w-10 text-muted/40" />
            <p className="mt-3 text-sm text-ink/80">No credentials stored</p>
            <p className="mx-auto mt-1 max-w-md text-xs leading-relaxed text-muted">
              Unauthenticated scans see only what is exposed on the network. A credential lets the
              platform read the actual configuration of a host, which is what turns guesswork into
              evidence.
            </p>
          </div>
        ) : (
          <div className="overflow-hidden rounded-xl border border-border bg-surface">
            <table className="w-full text-sm">
              <thead className="border-b border-border bg-surface-hover/40 text-left text-xs uppercase tracking-wider text-muted">
                <tr>
                  <th className="px-4 py-3 font-semibold">Name</th>
                  <th className="px-4 py-3 font-semibold">Type</th>
                  <th className="px-4 py-3 font-semibold">Account</th>
                  <th className="px-4 py-3 font-semibold">Secret</th>
                  <th className="px-4 py-3 font-semibold">Last used</th>
                  <th className="px-4 py-3 font-semibold">Rotated</th>
                  <th className="px-4 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {credentials.map((credential) => (
                  <tr key={credential.id} className="hover:bg-surface-hover/40">
                    <td className="px-4 py-3">
                      <p className="font-medium text-ink">{credential.name}</p>
                      {credential.description && (
                        <p className="text-xs text-muted">{credential.description}</p>
                      )}
                    </td>
                    <td className="px-4 py-3 text-muted">
                      {CREDENTIAL_TYPES.find((t) => t.value === credential.credential_type)?.label
                        ?? credential.credential_type}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-ink/90">
                      {credential.domain ? `${credential.domain}\\` : ""}
                      {credential.username || "—"}
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-2.5 py-1 font-mono text-xs text-muted">
                        <Lock className="h-3 w-3" /> encrypted
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-muted">
                      {credential.last_used_at
                        ? formatDistanceToNow(new Date(credential.last_used_at), { addSuffix: true })
                        : "never"}
                    </td>
                    <td className="px-4 py-3 text-xs text-muted">
                      {credential.rotated_at
                        ? formatDistanceToNow(new Date(credential.rotated_at), { addSuffix: true })
                        : "—"}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end gap-2">
                        <button
                          onClick={() => { setError(null); setRotating(credential); }}
                          className="text-muted transition-colors hover:text-primary"
                          title="Rotate secret"
                        >
                          <RefreshCw className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => remove.mutate(credential.id)}
                          className="text-muted transition-colors hover:text-critical"
                          title="Delete credential"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </main>

      <Modal open={createOpen} onClose={() => setCreateOpen(false)} title="Add credential">
        <CredentialForm
          error={error}
          pending={create.isPending}
          onSubmit={(body) => create.mutate(body)}
        />
      </Modal>

      <Modal open={rotating !== null} onClose={() => setRotating(null)} title="Rotate secret">
        <RotateForm
          name={rotating?.name ?? ""}
          error={error}
          pending={rotate.isPending}
          onSubmit={(secret) => rotating && rotate.mutate({ id: rotating.id, secret })}
        />
      </Modal>
    </>
  );
}

function CredentialForm({
  error, pending, onSubmit,
}: {
  error: string | null;
  pending: boolean;
  onSubmit: (body: Record<string, unknown>) => void;
}) {
  const [name, setName] = useState("");
  const [type, setType] = useState("windows");
  const [username, setUsername] = useState("");
  const [domain, setDomain] = useState("");
  const [secret, setSecret] = useState("");
  const [description, setDescription] = useState("");

  const secretLabel = SECRET_LABELS[type] ?? "Password";
  const isKey = type === "ssh_key";

  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit({ name, credential_type: type, username, domain, secret, description });
      }}
    >
      <div>
        <label className="mb-1 block text-xs font-medium text-muted">Name</label>
        <input className={inputClass} value={name} onChange={(e) => setName(e.target.value)} required placeholder="Domain scan account" />
      </div>

      <div>
        <label className="mb-1 block text-xs font-medium text-muted">Type</label>
        <select className={inputClass} value={type} onChange={(e) => setType(e.target.value)}>
          {CREDENTIAL_TYPES.map((option) => (
            <option key={option.value} value={option.value}>{option.label}</option>
          ))}
        </select>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="mb-1 block text-xs font-medium text-muted">Username</label>
          <input className={inputClass} value={username} onChange={(e) => setUsername(e.target.value)} placeholder="svc_scan" />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-muted">Domain</label>
          <input className={inputClass} value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="CORP" />
        </div>
      </div>

      <div>
        <label className="mb-1 block text-xs font-medium text-muted">{secretLabel}</label>
        {isKey ? (
          <textarea
            className={`${inputClass} h-32 font-mono text-xs`}
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            required
            placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
          />
        ) : (
          <input
            type="password"
            className={inputClass}
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            required
            autoComplete="new-password"
          />
        )}
        <p className="mt-1 text-[11px] leading-relaxed text-muted/80">
          Encrypted before it is stored. It will not be shown again — rotate it if you need to change it.
          Use an account with the least privilege the assessment requires.
        </p>
      </div>

      <div>
        <label className="mb-1 block text-xs font-medium text-muted">Description</label>
        <input className={inputClass} value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Read-only account for Windows configuration checks" />
      </div>

      {error && <p className="text-sm text-critical">{error}</p>}
      <Button type="submit" disabled={!name || !secret || pending} className="w-full">
        {pending ? "Encrypting…" : "Store credential"}
      </Button>
    </form>
  );
}

function RotateForm({
  name, error, pending, onSubmit,
}: {
  name: string;
  error: string | null;
  pending: boolean;
  onSubmit: (secret: string) => void;
}) {
  const [secret, setSecret] = useState("");

  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit(secret);
      }}
    >
      <p className="text-sm text-muted">
        Replace the stored secret for <span className="font-medium text-ink">{name}</span>. The
        previous value is overwritten and cannot be recovered.
      </p>
      <div>
        <label className="mb-1 block text-xs font-medium text-muted">New secret</label>
        <input
          type="password"
          className={inputClass}
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
          required
          autoComplete="new-password"
        />
      </div>
      {error && <p className="text-sm text-critical">{error}</p>}
      <Button type="submit" disabled={!secret || pending} className="w-full">
        {pending ? "Rotating…" : "Rotate secret"}
      </Button>
    </form>
  );
}
