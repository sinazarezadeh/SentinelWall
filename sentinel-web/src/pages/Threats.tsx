import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Shield, TrendingUp } from "lucide-react";
import { threatsApi } from "../api/client";
import { useWebSocket } from "../hooks/useWebSocket";
import { useState } from "react";
import { formatDistanceToNow } from "date-fns";

interface ThreatEntry {
  id: string;
  ip: string;
  threat_type: string;
  severity: string;
  description: string;
  timestamp: string;
  confidence: number;
}

export default function ThreatsPage() {
  const [liveThreats, setLiveThreats] = useState<ThreatEntry[]>([]);

  useWebSocket({
    onEvent: (event) => {
      if (event.type === "threat") {
        setLiveThreats((prev) => [
          {
            id: (event.data?.id as string) ?? crypto.randomUUID(),
            ip: (event.data?.ip as string) ?? "",
            threat_type: (event.data?.threat_type as string) ?? "",
            severity: (event.data?.severity as string) ?? "low",
            description: (event.data?.description as string) ?? "",
            timestamp: (event.data?.timestamp as string) ?? new Date().toISOString(),
            confidence: (event.data?.confidence as number) ?? 1.0,
          },
          ...prev.slice(0, 199),
        ]);
      }
    },
  });

  function SeverityBadge({ s }: { s: string }) {
    const m: Record<string, string> = {
      critical: "badge-critical",
      high: "badge-high",
      medium: "badge-medium",
      low: "badge-low",
    };
    return <span className={m[s.toLowerCase()] ?? "badge-low"}>{s.toUpperCase()}</span>;
  }

  return (
    <div className="p-6 space-y-4 animate-fade-in">
      <div>
        <h1 className="text-xl font-bold text-white">Threat Detection</h1>
        <p className="text-sm text-gray-500">Real-time threat intelligence feed</p>
      </div>

      <div className="card overflow-hidden p-0">
        <div className="px-4 py-3 bg-surface-secondary border-b border-surface-border flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-yellow-400" />
          <span className="text-sm font-medium text-white">Live Threats</span>
          <span className="ml-auto text-xs text-gray-500">{liveThreats.length} detected</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="border-b border-surface-border">
              <tr>
                <th className="text-left px-4 py-3 table-header">Time</th>
                <th className="text-left px-4 py-3 table-header">IP</th>
                <th className="text-left px-4 py-3 table-header">Type</th>
                <th className="text-left px-4 py-3 table-header">Severity</th>
                <th className="text-left px-4 py-3 table-header">Confidence</th>
                <th className="text-left px-4 py-3 table-header">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border">
              {liveThreats.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-12 text-center">
                    <div className="flex flex-col items-center gap-3 text-gray-500">
                      <Shield className="w-8 h-8 opacity-30" />
                      <p className="text-sm">No threats detected — all clear!</p>
                    </div>
                  </td>
                </tr>
              ) : (
                liveThreats.map((t) => (
                  <tr key={t.id} className="hover:bg-surface-hover transition-colors">
                    <td className="px-4 py-3 text-gray-400 text-xs font-mono whitespace-nowrap">
                      {formatDistanceToNow(new Date(t.timestamp), { addSuffix: true })}
                    </td>
                    <td className="px-4 py-3 font-mono text-sm text-red-300">{t.ip}</td>
                    <td className="px-4 py-3 text-white text-sm">{t.threat_type}</td>
                    <td className="px-4 py-3">
                      <SeverityBadge s={t.severity} />
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-sm">
                      {(t.confidence * 100).toFixed(0)}%
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-sm max-w-xs truncate">
                      {t.description}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
