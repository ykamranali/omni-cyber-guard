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
  is_active?: boolean;
}

const BLANK: UserFormValues = {
  email: "", full_name: "", password: "", role_names: [], is_active: true,
};

/**
 * Create *and* edit.
 *
 * There was no way to change a user at all once created: no rename, no role
 * reassignment, and no way to reactivate an account after deactivating it — so
 * a wrong role, or a deactivation done in error, was permanent.
 *
 * Email is deliberately immutable when editing: it identifies the account
 * across the audit trail, and the API does not accept a change to it.
 */
export function UserFormModal({
  open, onClose, onSubmit, submitting, roles, initialValues, error,
}: {
  open: boolean;
  onClose: () => void;
  onSubmit: (values: UserFormValues) => void;
  submitting: boolean;
  roles: RoleOut[];
  initialValues?: UserFormValues | null;
  error?: string | null;
}) {
  const editing = Boolean(initialValues);
  const [values, setValues] = useState<UserFormValues>(initialValues ?? BLANK);

  useEffect(() => {
    if (open) setValues(initialValues ?? BLANK);
  }, [open, initialValues]);

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
    <Modal open={open} onClose={onClose} title={editing ? "Edit User" : "Add User"}>
      <form onSubmit={handleSubmit} className="space-y-3">
        <div>
          <label className="mb-1 block text-xs text-muted">Full name *</label>
          <Input required value={values.full_name} onChange={(e) => setValues((v) => ({ ...v, full_name: e.target.value }))} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-muted">Email *</label>
          <Input
            required
            type="email"
            value={values.email}
            disabled={editing}
            onChange={(e) => setValues((v) => ({ ...v, email: e.target.value }))}
          />
          {editing && (
            <p className="mt-1 text-[11px] text-muted">
              The address identifies this account across the audit trail and
              cannot be changed here.
            </p>
          )}
        </div>
        {!editing && (
          <div>
            <label className="mb-1 block text-xs text-muted">Temporary password *</label>
            <Input
              required
              type="password"
              minLength={8}
              value={values.password}
              onChange={(e) => setValues((v) => ({ ...v, password: e.target.value }))}
            />
          </div>
        )}
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

        {editing && (
          <label className="flex items-start gap-3 rounded-lg border border-border bg-surface-hover/40 p-3">
            <input
              type="checkbox"
              checked={values.is_active ?? true}
              onChange={(e) => setValues((v) => ({ ...v, is_active: e.target.checked }))}
              className="mt-1"
            />
            <span className="text-sm">
              <span className="font-medium text-ink">Account is active</span>
              <span className="mt-0.5 block text-xs leading-relaxed text-muted">
                Deactivating blocks sign-in and closes any live session. The
                account and its audit history are kept — this is how you reverse
                a deactivation.
              </span>
            </span>
          </label>
        )}

        {error && (
          <p className="rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-2 text-xs text-red-400">
            {error}
          </p>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
          <Button type="submit" disabled={submitting}>
            {submitting ? "Saving…" : editing ? "Save Changes" : "Create User"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
