import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, Search, Shield, Clock, AlertCircle } from "lucide-react";
import toast from "react-hot-toast";
import { bansApi } from "../api/client";
import { formatDistanceToNow } from "date-fns";

interface Ban {
  ip: string;
  reason: string;
  banned_at: string;
  expires_at: string | null;
  ban_count: number;
  source: string;
}

export default function BansPage() {
  const [search, setSearch] = useState("");
  const [showBanForm, setShowBanForm] = useState(false);
  const qc = useQueryClient();

  const { data: bansData, isLoading } = useQuery({
    queryKey: ["bans"],
    queryFn: () => bansApi.list().then((r) => r.data),
    refetchInterval: 10000,
  });

  const unban = useMutation({
    mutationFn: (ip: string) => bansApi.unban(ip),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["bans"] });
      toast.success("IP unbanned");
    },
    onError: () => toast.error("Failed to unban IP"),
  });

  const bans: Ban[] = bansData?.data ?? [];
  const filtered = search
    ? bans.filter((b) => b.ip.includes(search) || b.reason.toLowerCase().includes(search.toLowerCase()))
    : bans;

  return (
    <div className="p-6 space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">IP Bans</h1>
          <p className="text-sm text-gray-500">{bans.length} active bans</p>
        </div>
        <button
          onClick={() => setShowBanForm(true)}
          className="btn-primary flex items-center gap-2 text-sm"
        >
          <Plus className="w-4 h-4" />
          Ban IP
        </button>
      </div>

      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
        <input
          type="text"
          placeholder="Search by IP or reason…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="input-field w-full pl-9 text-sm"
        />
      </div>

      <div className="card overflow-hidden p-0">
        <table className="w-full">
          <thead className="bg-surface-secondary border-b border-surface-border">
            <tr>
              <th className="text-left px-4 py-3 table-header">IP Address</th>
              <th className="text-left px-4 py-3 table-header">Reason</th>
              <th className="text-left px-4 py-3 table-header">Banned</th>
              <th className="text-left px-4 py-3 table-header">Expires</th>
              <th className="text-left px-4 py-3 table-header">Source</th>
              <th className="text-left px-4 py-3 table-header">#</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-surface-border">
            {isLoading ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-gray-500">Loading bans…</td>
              </tr>
            ) : filtered.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-gray-500">
                  {search ? "No bans matching search" : "No active bans"}
                </td>
              </tr>
            ) : (
              filtered.map((ban) => (
                <tr key={ban.ip} className="hover:bg-surface-hover transition-colors">
                  <td className="px-4 py-3">
                    <span className="font-mono text-sm text-red-300">{ban.ip}</span>
                  </td>
                  <td className="px-4 py-3 text-gray-300 text-sm">{ban.reason}</td>
                  <td className="px-4 py-3 text-gray-400 text-xs">
                    {ban.banned_at ? formatDistanceToNow(new Date(ban.banned_at), { addSuffix: true }) : "—"}
                  </td>
                  <td className="px-4 py-3">
                    {ban.expires_at ? (
                      <span className="text-yellow-400 text-xs font-mono">
                        {formatDistanceToNow(new Date(ban.expires_at), { addSuffix: true })}
                      </span>
                    ) : (
                      <span className="text-red-400 text-xs font-semibold">Permanent</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-gray-500 text-xs">{ban.source}</td>
                  <td className="px-4 py-3 text-gray-400 text-sm">{ban.ban_count}</td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => {
                        if (confirm(`Unban ${ban.ip}?`)) unban.mutate(ban.ip);
                      }}
                      className="text-gray-500 hover:text-green-400 transition-colors text-xs"
                    >
                      Unban
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {showBanForm && (
        <BanModal
          onClose={() => setShowBanForm(false)}
          onSuccess={() => {
            setShowBanForm(false);
            qc.invalidateQueries({ queryKey: ["bans"] });
          }}
        />
      )}
    </div>
  );
}

function BanModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const [ip, setIp] = useState("");
  const [reason, setReason] = useState("Manual ban");
  const [duration, setDuration] = useState("3600");
  const [permanent, setPermanent] = useState(false);

  const ban = useMutation({
    mutationFn: ({ ip, reason, duration, permanent }: any) =>
      bansApi.ban(ip, reason, permanent ? undefined : parseInt(duration), permanent),
    onSuccess: () => {
      toast.success(`${ip} banned`);
      onSuccess();
    },
    onError: () => toast.error("Failed to ban IP"),
  });

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-surface-card border border-surface-border rounded-xl w-full max-w-md">
        <div className="p-6 border-b border-surface-border">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-red-400" />
            Ban IP Address
          </h2>
        </div>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            ban.mutate({ ip, reason, duration, permanent });
          }}
          className="p-6 space-y-4"
        >
          <div>
            <label className="block text-sm text-gray-400 mb-1">IP Address</label>
            <input
              type="text"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              className="input-field w-full font-mono"
              placeholder="e.g., 1.2.3.4"
              required
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Reason</label>
            <input
              type="text"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="input-field w-full"
              required
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Duration (seconds)</label>
            <input
              type="number"
              value={duration}
              onChange={(e) => setDuration(e.target.value)}
              className="input-field w-full"
              disabled={permanent}
            />
          </div>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={permanent}
              onChange={(e) => setPermanent(e.target.checked)}
              className="w-4 h-4"
            />
            <span className="text-sm text-gray-400">Permanent ban</span>
          </label>
          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose} className="btn-secondary flex-1">Cancel</button>
            <button type="submit" disabled={ban.isPending} className="btn-danger flex-1">
              {ban.isPending ? "Banning…" : "Ban IP"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
