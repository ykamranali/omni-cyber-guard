"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, UserX, CheckCircle2 } from "lucide-react";

import { Topbar } from "@/components/layout/topbar";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { UserFormModal, UserFormValues, RoleOut } from "@/components/users/user-form-modal";
import { api, ApiError } from "@/lib/api";
import { useAuthStore } from "@/store/auth";

interface UserOut {
  id: string;
  email: string;
  full_name: string;
  is_active: boolean;
  is_super_admin: boolean;
  roles: string[];
}

export default function UsersPage() {
  const queryClient = useQueryClient();
  const currentUser = useAuthStore((s) => s.user);
  const [modalOpen, setModalOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { data: users, isLoading, isError } = useQuery({
    queryKey: ["users"],
    queryFn: () => api.get<UserOut[]>("/users"),
  });
  const { data: roles } = useQuery({
    queryKey: ["roles"],
    queryFn: () => api.get<RoleOut[]>("/users/roles/available"),
  });

  const createUser = useMutation({
    mutationFn: (values: UserFormValues) => api.post<UserOut>("/users", values),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users"] });
      setModalOpen(false);
      setError(null);
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : "Failed to create user"),
  });

  const deactivateUser = useMutation({
    mutationFn: (id: string) => api.delete(`/users/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["users"] }),
  });

  return (
    <>
      <Topbar title="Users" />
      <main className="flex-1 space-y-4 overflow-y-auto p-6">
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted">Manage users within your organization and their assigned roles.</p>
          <Button onClick={() => setModalOpen(true)}>
            <Plus size={15} /> Add User
          </Button>
        </div>

        {error && <p className="rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">{error}</p>}

        <Card className="overflow-hidden p-0">
          {isLoading && <p className="p-6 text-sm text-muted">Loading users…</p>}
          {isError && <p className="p-6 text-sm text-critical">Unable to load users — you may not have permission to manage users.</p>}

          {users && (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-border bg-surface-hover/50 text-xs uppercase tracking-wide text-muted">
                  <tr>
                    <th className="px-4 py-3 font-medium">Name</th>
                    <th className="px-4 py-3 font-medium">Email</th>
                    <th className="px-4 py-3 font-medium">Roles</th>
                    <th className="px-4 py-3 font-medium">Status</th>
                    <th className="px-4 py-3 font-medium"></th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id} className="border-b border-border/60 hover:bg-surface-hover/40">
                      <td className="px-4 py-3 font-medium text-ink">
                        {u.full_name} {u.id === currentUser?.id && <span className="text-xs text-muted">(you)</span>}
                      </td>
                      <td className="px-4 py-3 text-ink/75">{u.email}</td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {u.is_super_admin && <Badge label="super admin" />}
                          {u.roles.map((r) => <Badge key={r} label={r} />)}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        {u.is_active ? (
                          <span className="flex items-center gap-1 text-xs text-low"><CheckCircle2 size={13} /> Active</span>
                        ) : (
                          <span className="flex items-center gap-1 text-xs text-muted"><UserX size={13} /> Deactivated</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right">
                        {u.is_active && u.id !== currentUser?.id && (
                          <button
                            onClick={() => deactivateUser.mutate(u.id)}
                            className="rounded-md p-1.5 text-muted hover:bg-critical/10 hover:text-critical"
                            title="Deactivate user"
                          >
                            <UserX size={15} />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </main>

      <UserFormModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        submitting={createUser.isPending}
        roles={roles || []}
        onSubmit={(values) => createUser.mutate(values)}
      />
    </>
  );
}
