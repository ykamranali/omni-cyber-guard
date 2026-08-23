"use client";

import { FormEvent, useEffect, useState } from "react";
import { Modal } from "@/components/ui/modal";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

const ASSET_TYPES = ["server", "workstation", "network_device", "mobile_device", "cloud_resource", "iot_device", "application", "other"];

export interface AssetFormValues {
  hostname: string;
  ip_address: string;
  asset_type: string;
  operating_system: string;
  vendor: string;
  site: string;
  department: string;
}

const BLANK: AssetFormValues = {
  hostname: "", ip_address: "", asset_type: "server", operating_system: "",
  vendor: "", site: "", department: "",
};

/**
 * Create *and* edit.
 *
 * Only `criticality` was ever editable, through a select in the drawer. An
 * asset's hostname, address, type, operating system, vendor, site and
 * department could be entered once and never corrected — so a typo at creation
 * time, or a machine that was renamed, was permanent.
 */
export function AssetFormModal({
  open,
  onClose,
  onSubmit,
  submitting,
  initialValues,
  error,
}: {
  open: boolean;
  onClose: () => void;
  onSubmit: (values: AssetFormValues) => void;
  submitting: boolean;
  /** Present when editing; absent when creating. */
  initialValues?: AssetFormValues | null;
  error?: string | null;
}) {
  const editing = Boolean(initialValues);
  const [values, setValues] = useState<AssetFormValues>(initialValues ?? BLANK);

  // Re-seed whenever the modal is opened for a different asset, otherwise the
  // form keeps whatever was typed for the previous one.
  useEffect(() => {
    if (open) setValues(initialValues ?? BLANK);
  }, [open, initialValues]);

  function update<K extends keyof AssetFormValues>(key: K, value: AssetFormValues[K]) {
    setValues((v) => ({ ...v, [key]: value }));
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    onSubmit(values);
  }

  return (
    <Modal open={open} onClose={onClose} title={editing ? "Edit Asset" : "Add Asset"}>
      <form onSubmit={handleSubmit} className="space-y-3">
        <div>
          <label className="mb-1 block text-xs text-muted">Hostname *</label>
          <Input required value={values.hostname} onChange={(e) => update("hostname", e.target.value)} />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="mb-1 block text-xs text-muted">IP Address</label>
            <Input value={values.ip_address} onChange={(e) => update("ip_address", e.target.value)} />
          </div>
          <div>
            <label className="mb-1 block text-xs text-muted">Asset Type</label>
            <select
              className="h-10 w-full rounded-lg border border-border bg-surface/80 px-3 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-primary/40"
              value={values.asset_type}
              onChange={(e) => update("asset_type", e.target.value)}
            >
              {ASSET_TYPES.map((t) => (
                <option key={t} value={t}>{t.replace(/_/g, " ")}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="mb-1 block text-xs text-muted">Operating System</label>
            <Input value={values.operating_system} onChange={(e) => update("operating_system", e.target.value)} />
          </div>
          <div>
            <label className="mb-1 block text-xs text-muted">Vendor</label>
            <Input value={values.vendor} onChange={(e) => update("vendor", e.target.value)} />
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="mb-1 block text-xs text-muted">Site</label>
            <Input value={values.site} onChange={(e) => update("site", e.target.value)} />
          </div>
          <div>
            <label className="mb-1 block text-xs text-muted">Department</label>
            <Input value={values.department} onChange={(e) => update("department", e.target.value)} />
          </div>
        </div>

        {error && (
          <p className="rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-2 text-xs text-red-400">
            {error}
          </p>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
          <Button type="submit" disabled={submitting}>
            {submitting ? "Saving…" : editing ? "Save Changes" : "Add Asset"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
