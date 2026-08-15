"use client";

import { FormEvent, useState } from "react";
import { Modal } from "@/components/ui/modal";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

export interface OrgFormValues {
  name: string;
  slug: string;
  admin_full_name: string;
  admin_email: string;
  admin_password: string;
}

export function OrgFormModal({
  open, onClose, onSubmit, submitting,
}: {
  open: boolean;
  onClose: () => void;
  onSubmit: (values: OrgFormValues) => void;
  submitting: boolean;
}) {
  const [values, setValues] = useState<OrgFormValues>({
    name: "", slug: "", admin_full_name: "", admin_email: "", admin_password: "",
  });

  function update<K extends keyof OrgFormValues>(key: K, v: OrgFormValues[K]) {
    setValues((prev) => ({ ...prev, [key]: v }));
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    onSubmit(values);
  }

  return (
    <Modal open={open} onClose={onClose} title="Create Organization">
      <form onSubmit={handleSubmit} className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="mb-1 block text-xs text-muted">Organization name *</label>
            <Input required value={values.name} onChange={(e) => update("name", e.target.value)} />
          </div>
          <div>
            <label className="mb-1 block text-xs text-muted">Slug *</label>
            <Input required placeholder="acme-corp" value={values.slug} onChange={(e) => update("slug", e.target.value)} />
          </div>
        </div>
        <p className="pt-1 text-xs font-medium uppercase tracking-wide text-muted">Initial organization administrator</p>
        <div>
          <label className="mb-1 block text-xs text-muted">Full name *</label>
          <Input required value={values.admin_full_name} onChange={(e) => update("admin_full_name", e.target.value)} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-muted">Email *</label>
          <Input required type="email" value={values.admin_email} onChange={(e) => update("admin_email", e.target.value)} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-muted">Temporary password *</label>
          <Input required type="password" minLength={8} value={values.admin_password} onChange={(e) => update("admin_password", e.target.value)} />
        </div>

        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
          <Button type="submit" disabled={submitting}>{submitting ? "Creating…" : "Create Organization"}</Button>
        </div>
      </form>
    </Modal>
  );
}
