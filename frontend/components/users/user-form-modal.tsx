"use client";

import { FormEvent, useEffect, useState } from "react";
import { Modal } from "@/components/ui/modal";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

export interface RoleOut { id: string; name: string; is_system_role: boolean }

export interface UserFormValues {
  email: string;
  full_name: string;
  password: string;
  role_names: string[];
}

export function UserFormModal({
  open, onClose, onSubmit, submitting, roles,
}: {
  open: boolean;
  onClose: () => void;
  onSubmit: (values: UserFormValues) => void;
  submitting: boolean;
  roles: RoleOut[];
}) {
  const [values, setValues] = useState<UserFormValues>({ email: "", full_name: "", password: "", role_names: [] });

  useEffect(() => {
    if (!open) setValues({ email: "", full_name: "", password: "", role_names: [] });
  }, [open]);

  function toggleRole(name: string) {
    setValues((v) => ({
      ...v,
      role_names: v.role_names.includes(name) ? v.role_names.filter((r) => r !== name) : [...v.role_names, name],
    }));
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    onSubmit(values);
  }

  return (
    <Modal open={open} onClose={onClose} title="Add User">
      <form onSubmit={handleSubmit} className="space-y-3">
        <div>
          <label className="mb-1 block text-xs text-muted">Full name *</label>
          <Input required value={values.full_name} onChange={(e) => setValues((v) => ({ ...v, full_name: e.target.value }))} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-muted">Email *</label>
          <Input required type="email" value={values.email} onChange={(e) => setValues((v) => ({ ...v, email: e.target.value }))} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-muted">Temporary password *</label>
          <Input required type="password" minLength={8} value={values.password} onChange={(e) => setValues((v) => ({ ...v, password: e.target.value }))} />
        </div>
        <div>
          <label className="mb-1.5 block text-xs text-muted">Roles</label>
          <div className="flex flex-wrap gap-2">
            {roles.map((r) => (
              <button
                type="button"
                key={r.id}
                onClick={() => toggleRole(r.name)}
                className={`rounded-full border px-2.5 py-1 text-xs capitalize transition-colors ${
                  values.role_names.includes(r.name)
                    ? "border-primary/40 bg-primary/15 text-primary"
                    : "border-border text-ink/70 hover:bg-surface-hover"
                }`}
              >
                {r.name.replace(/_/g, " ")}
              </button>
            ))}
          </div>
        </div>

        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
          <Button type="submit" disabled={submitting}>{submitting ? "Saving…" : "Create User"}</Button>
        </div>
      </form>
    </Modal>
  );
}
