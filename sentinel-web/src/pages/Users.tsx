import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import toast from "react-hot-toast";
import { usersApi } from "../api/client";

export default function UsersPage() {
  const [showAdd, setShowAdd] = useState(false);
  const qc = useQueryClient();

  const { data } = useQuery({
    queryKey: ["users"],
    queryFn: () => usersApi.list().then((r) => r.data),
  });

  const users = data?.data ?? [];

  return (
    <div className="p-6 space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Users</h1>
          <p className="text-sm text-gray-500">Manage dashboard access</p>
        </div>
        <button onClick={() => setShowAdd(true)} className="btn-primary flex items-center gap-2 text-sm">
          <Plus className="w-4 h-4" />
          Add User
        </button>
      </div>

      <div className="card overflow-hidden p-0">
        <table className="w-full">
          <thead className="bg-surface-secondary border-b border-surface-border">
            <tr>
              <th className="text-left px-4 py-3 table-header">Username</th>
              <th className="text-left px-4 py-3 table-header">Role</th>
              <th className="text-left px-4 py-3 table-header">ID</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-surface-border">
            {users.map((u: any) => (
              <tr key={u.id} className="hover:bg-surface-hover">
                <td className="px-4 py-3 text-white font-medium">{u.username}</td>
                <td className="px-4 py-3">
                  <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${
                    u.role === "admin" ? "bg-red-500/20 text-red-400" :
                    u.role === "operator" ? "bg-yellow-500/20 text-yellow-400" :
                    "bg-gray-500/20 text-gray-400"
                  }`}>
                    {u.role}
                  </span>
                </td>
                <td className="px-4 py-3 text-gray-500 text-xs font-mono">{u.id}</td>
                <td className="px-4 py-3">
                  {u.username !== "admin" && (
                    <button className="text-gray-500 hover:text-red-400">
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
