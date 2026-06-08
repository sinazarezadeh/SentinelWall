import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, ToggleLeft, ToggleRight, Download, Upload, Filter } from "lucide-react";
import toast from "react-hot-toast";
import { rulesApi } from "../api/client";
import { clsx } from "clsx";

interface Rule {
  id: string;
  name: string;
  action: string;
  protocol: string;
  dst_port?: { type: string; value: number };
  src_addr?: { type: string; value: string };
  priority: number;
  enabled: boolean;
  hit_count: number;
  created_at: string;
}

export default function RulesPage() {
  const [filter, setFilter] = useState("");
  const [showAddForm, setShowAddForm] = useState(false);
  const qc = useQueryClient();

  const { data: rulesData, isLoading } = useQuery({
    queryKey: ["rules"],
    queryFn: () => rulesApi.list().then((r) => r.data),
    refetchInterval: 10000,
  });

  const deleteRule = useMutation({
    mutationFn: (id: string) => rulesApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["rules"] });
      toast.success("Rule deleted");
    },
    onError: () => toast.error("Failed to delete rule"),
  });

  const flushRules = useMutation({
    mutationFn: () => rulesApi.flush(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["rules"] });
      toast.success("All rules flushed");
    },
    onError: () => toast.error("Failed to flush rules"),
  });

  const rules: Rule[] = rulesData?.data ?? [];
  const filtered = filter
    ? rules.filter(
        (r) =>
          r.name.toLowerCase().includes(filter.toLowerCase()) ||
          r.protocol.toLowerCase().includes(filter.toLowerCase()) ||
          r.action.toLowerCase().includes(filter.toLowerCase())
      )
    : rules;

  return (
    <div className="p-6 space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Firewall Rules</h1>
          <p className="text-sm text-gray-500">{rules.length} rules configured</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowAddForm(true)}
            className="btn-primary flex items-center gap-2 text-sm"
          >
            <Plus className="w-4 h-4" />
            Add Rule
          </button>
          <button
            onClick={() => {
              if (confirm("Flush ALL rules?")) flushRules.mutate();
            }}
            className="btn-danger flex items-center gap-2 text-sm"
          >
            Flush All
          </button>
        </div>
      </div>

      {/* Filter */}
      <div className="flex gap-3">
        <div className="relative flex-1 max-w-sm">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            placeholder="Filter rules…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="input-field w-full pl-9 text-sm"
          />
        </div>
      </div>

      {/* Table */}
      <div className="card overflow-hidden p-0">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-surface-secondary border-b border-surface-border">
              <tr>
                <th className="text-left px-4 py-3 table-header">Priority</th>
                <th className="text-left px-4 py-3 table-header">Name</th>
                <th className="text-left px-4 py-3 table-header">Action</th>
                <th className="text-left px-4 py-3 table-header">Protocol</th>
                <th className="text-left px-4 py-3 table-header">Port</th>
                <th className="text-left px-4 py-3 table-header">Source</th>
                <th className="text-left px-4 py-3 table-header">Hits</th>
                <th className="text-left px-4 py-3 table-header">Status</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border">
              {isLoading ? (
                <tr>
                  <td colSpan={9} className="px-4 py-8 text-center text-gray-500">
                    Loading rules…
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={9} className="px-4 py-8 text-center text-gray-500">
                    {filter ? "No rules matching filter" : "No rules configured"}
                  </td>
                </tr>
              ) : (
                filtered.map((rule) => (
                  <tr key={rule.id} className="hover:bg-surface-hover transition-colors">
                    <td className="px-4 py-3 text-gray-400 text-sm font-mono">
                      {rule.priority}
                    </td>
                    <td className="px-4 py-3 text-white text-sm font-medium">
                      {rule.name}
                    </td>
                    <td className="px-4 py-3">
                      <span className={rule.action === "accept" ? "badge-allow" : "badge-deny"}>
                        {rule.action.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-300 text-sm font-mono">
                      {rule.protocol}
                    </td>
                    <td className="px-4 py-3 text-gray-300 text-sm font-mono">
                      {rule.dst_port?.value ?? "any"}
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-sm font-mono">
                      {rule.src_addr?.value ?? "any"}
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-sm font-mono">
                      {rule.hit_count?.toLocaleString() ?? 0}
                    </td>
                    <td className="px-4 py-3">
                      {rule.enabled ? (
                        <span className="text-green-400 text-xs">Enabled</span>
                      ) : (
                        <span className="text-gray-500 text-xs">Disabled</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => {
                          if (confirm(`Delete rule "${rule.name}"?`)) {
                            deleteRule.mutate(rule.id);
                          }
                        }}
                        className="text-gray-500 hover:text-red-400 transition-colors"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {showAddForm && (
        <AddRuleModal
          onClose={() => setShowAddForm(false)}
          onSuccess={() => {
            setShowAddForm(false);
            qc.invalidateQueries({ queryKey: ["rules"] });
          }}
        />
      )}
    </div>
  );
}

function AddRuleModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const [name, setName] = useState("");
  const [action, setAction] = useState("accept");
  const [protocol, setProtocol] = useState("tcp");
  const [port, setPort] = useState("");
  const [from, setFrom] = useState("");
  const [priority, setPriority] = useState("100");

  const addRule = useMutation({
    mutationFn: (rule: any) => rulesApi.create(rule),
    onSuccess: () => {
      toast.success("Rule created");
      onSuccess();
    },
    onError: () => toast.error("Failed to create rule"),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const rule: any = {
      id: crypto.randomUUID(),
      name,
      action,
      protocol,
      priority: parseInt(priority),
      enabled: true,
      direction: "inbound",
      log: false,
      tags: [],
      hit_count: 0,
      source: "manual",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    if (port) rule.dst_port = { type: "Single", value: parseInt(port) };
    if (from) rule.src_addr = from.includes("/")
      ? { type: "Network", value: from }
      : { type: "Single", value: from };
    addRule.mutate(rule);
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-surface-card border border-surface-border rounded-xl w-full max-w-md">
        <div className="p-6 border-b border-surface-border">
          <h2 className="text-lg font-semibold text-white">Add Firewall Rule</h2>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Rule Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="input-field w-full"
              placeholder="e.g., allow-https"
              required
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-sm text-gray-400 mb-1">Action</label>
              <select
                value={action}
                onChange={(e) => setAction(e.target.value)}
                className="input-field w-full"
              >
                <option value="accept">Allow</option>
                <option value="drop">Drop</option>
                <option value="reject">Reject</option>
              </select>
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Protocol</label>
              <select
                value={protocol}
                onChange={(e) => setProtocol(e.target.value)}
                className="input-field w-full"
              >
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="icmp">ICMP</option>
                <option value="any">Any</option>
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-sm text-gray-400 mb-1">Port</label>
              <input
                type="number"
                value={port}
                onChange={(e) => setPort(e.target.value)}
                className="input-field w-full"
                placeholder="e.g., 443"
                min="1" max="65535"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Priority</label>
              <input
                type="number"
                value={priority}
                onChange={(e) => setPriority(e.target.value)}
                className="input-field w-full"
              />
            </div>
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Source IP/CIDR (optional)</label>
            <input
              type="text"
              value={from}
              onChange={(e) => setFrom(e.target.value)}
              className="input-field w-full"
              placeholder="e.g., 192.168.1.0/24"
            />
          </div>
          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose} className="btn-secondary flex-1">
              Cancel
            </button>
            <button type="submit" disabled={addRule.isPending} className="btn-primary flex-1">
              {addRule.isPending ? "Creating…" : "Create Rule"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
