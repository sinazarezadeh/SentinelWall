import { useQuery } from "@tanstack/react-query";
import { useState, useEffect } from "react";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, CartesianGrid
} from "recharts";
import {
  Shield, AlertTriangle, Ban, ScrollText, Activity,
  TrendingUp, Zap, Clock
} from "lucide-react";
import { statusApi, threatsApi } from "../api/client";
import { useWebSocket } from "../hooks/useWebSocket";
import { format } from "date-fns";

interface LiveEvent {
  type: string;
  data: Record<string, unknown>;
  timestamp: Date;
}

function StatCard({
  icon: Icon,
  label,
  value,
  delta,
  color = "blue",
}: {
  icon: React.ElementType;
  label: string;
  value: string | number;
  delta?: string;
  color?: "blue" | "red" | "green" | "yellow";
}) {
  const colors = {
    blue: "text-blue-400 bg-blue-400/10",
    red: "text-red-400 bg-red-400/10",
    green: "text-green-400 bg-green-400/10",
    yellow: "text-yellow-400 bg-yellow-400/10",
  };

  return (
    <div className="stat-card">
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">{label}</span>
        <div className={`p-2 rounded-lg ${colors[color]}`}>
          <Icon className="w-4 h-4" />
        </div>
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      {delta && (
        <div className="text-xs text-gray-500 mt-1">{delta}</div>
      )}
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const classes: Record<string, string> = {
    critical: "badge-critical",
    high: "badge-high",
    medium: "badge-medium",
    low: "badge-low",
  };
  return (
    <span className={classes[severity.toLowerCase()] ?? "badge-low"}>
      {severity.toUpperCase()}
    </span>
  );
}

export default function DashboardPage() {
  const [liveEvents, setLiveEvents] = useState<LiveEvent[]>([]);
  const [activityData, setActivityData] = useState(
    Array.from({ length: 20 }, (_, i) => ({
      time: format(new Date(Date.now() - (19 - i) * 30000), "HH:mm:ss"),
      threats: 0,
      bans: 0,
    }))
  );

  const { data: status, isLoading } = useQuery({
    queryKey: ["status"],
    queryFn: () => statusApi.get().then((r) => r.data?.data ?? r.data),
    refetchInterval: 5000,
  });

  const { events, connected } = useWebSocket({
    onEvent: (event) => {
      setLiveEvents((prev) => [
        { ...event, timestamp: new Date() },
        ...prev.slice(0, 49),
      ]);

      if (event.type === "threat" || event.type === "ban") {
        setActivityData((prev) => {
          const updated = [...prev];
          const last = { ...updated[updated.length - 1] };
          if (event.type === "threat") last.threats++;
          if (event.type === "ban") last.bans++;
          updated[updated.length - 1] = last;
          return updated;
        });
      }
    },
  });

  const statusData = status ?? {};

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Dashboard</h1>
          <p className="text-sm text-gray-500">Real-time firewall overview</p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <div className={`w-1.5 h-1.5 rounded-full ${connected ? "bg-green-400 animate-pulse" : "bg-red-400"}`} />
          <span className={connected ? "text-green-400" : "text-red-400"}>
            {connected ? "Live" : "Offline"}
          </span>
        </div>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={ScrollText}
          label="Active Rules"
          value={isLoading ? "—" : (statusData.rules_count ?? 0)}
          color="blue"
        />
        <StatCard
          icon={Ban}
          label="Active Bans"
          value={isLoading ? "—" : (statusData.bans_count ?? 0)}
          color="red"
        />
        <StatCard
          icon={AlertTriangle}
          label="Threats Today"
          value={isLoading ? "—" : (statusData.threats_today ?? 0)}
          color="yellow"
        />
        <StatCard
          icon={Clock}
          label="Uptime"
          value={formatUptime(statusData.uptime_seconds ?? 0)}
          color="green"
        />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Activity chart */}
        <div className="card">
          <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <Activity className="w-4 h-4 text-sentinel-400" />
            Live Activity
          </h3>
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={activityData}>
              <defs>
                <linearGradient id="threatsGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ff4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ff4444" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="bansGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#253047" />
              <XAxis dataKey="time" tick={{ fontSize: 10, fill: "#6b7280" }} />
              <YAxis tick={{ fontSize: 10, fill: "#6b7280" }} />
              <Tooltip
                contentStyle={{
                  background: "#1a2035",
                  border: "1px solid #253047",
                  borderRadius: "8px",
                  color: "#fff",
                  fontSize: "12px",
                }}
              />
              <Area type="monotone" dataKey="threats" stroke="#ff4444" fill="url(#threatsGrad)" strokeWidth={2} name="Threats" />
              <Area type="monotone" dataKey="bans" stroke="#3b82f6" fill="url(#bansGrad)" strokeWidth={2} name="Bans" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Live events feed */}
        <div className="card">
          <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <Zap className="w-4 h-4 text-yellow-400" />
            Live Events
            <span className="ml-auto text-xs text-gray-500">{liveEvents.length} events</span>
          </h3>
          <div className="space-y-1.5 max-h-[180px] overflow-y-auto">
            {liveEvents.length === 0 ? (
              <p className="text-sm text-gray-600 text-center py-4">
                Waiting for events…
              </p>
            ) : (
              liveEvents.slice(0, 10).map((event, i) => (
                <div key={i} className="flex items-start gap-2 text-xs py-1 border-b border-surface-border/50">
                  <span className="text-gray-600 font-mono flex-shrink-0">
                    {format(event.timestamp, "HH:mm:ss")}
                  </span>
                  <EventBadge type={event.type} />
                  <span className="text-gray-400 truncate">
                    {getEventDescription(event)}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* System info */}
      <div className="card">
        <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
          <Shield className="w-4 h-4 text-sentinel-400" />
          System Status
        </h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div>
            <div className="text-gray-500 text-xs mb-1">Backend</div>
            <div className="text-white font-medium">{statusData.backend ?? "nftables"}</div>
          </div>
          <div>
            <div className="text-gray-500 text-xs mb-1">Version</div>
            <div className="text-white font-medium font-mono">{statusData.version ?? "—"}</div>
          </div>
          <div>
            <div className="text-gray-500 text-xs mb-1">Status</div>
            <div className="text-green-400 font-medium capitalize">{statusData.status ?? "—"}</div>
          </div>
          <div>
            <div className="text-gray-500 text-xs mb-1">WS Events</div>
            <div className="text-white font-medium">{liveEvents.length}</div>
          </div>
        </div>
      </div>
    </div>
  );
}

function EventBadge({ type }: { type: string }) {
  const styles: Record<string, string> = {
    threat: "bg-red-500/20 text-red-400",
    ban: "bg-orange-500/20 text-orange-400",
    unban: "bg-green-500/20 text-green-400",
    rule_added: "bg-blue-500/20 text-blue-400",
    rule_removed: "bg-gray-500/20 text-gray-400",
    connected: "bg-green-500/20 text-green-400",
  };
  return (
    <span className={`px-1.5 py-0.5 rounded text-xs font-medium flex-shrink-0 ${styles[type] ?? "bg-gray-500/20 text-gray-400"}`}>
      {type}
    </span>
  );
}

function getEventDescription(event: LiveEvent): string {
  switch (event.type) {
    case "threat":
      return `${event.data?.ip} — ${event.data?.threat_type}`;
    case "ban":
      return `${event.data?.ip} banned: ${event.data?.reason}`;
    case "unban":
      return `${event.data?.ip} unbanned`;
    case "rule_added":
      return `Rule added: ${event.data?.name}`;
    case "connected":
      return "Connected to event stream";
    default:
      return JSON.stringify(event.data).slice(0, 60);
  }
}

function formatUptime(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
  return `${Math.floor(secs / 86400)}d ${Math.floor((secs % 86400) / 3600)}h`;
}
