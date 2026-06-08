import { useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line, Legend } from "recharts";
import { BarChart3 } from "lucide-react";

const MOCK_DAILY = Array.from({ length: 7 }, (_, i) => ({
  day: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][i],
  threats: Math.floor(Math.random() * 100),
  bans: Math.floor(Math.random() * 40),
  connections: Math.floor(Math.random() * 5000) + 1000,
}));

const MOCK_THREAT_TYPES = [
  { name: "Brute Force", value: 45, color: "#ff4444" },
  { name: "Port Scan", value: 25, color: "#ff7700" },
  { name: "SYN Flood", value: 15, color: "#ffcc00" },
  { name: "HTTP Flood", value: 10, color: "#4499ff" },
  { name: "Other", value: 5, color: "#8888ff" },
];

export default function AnalyticsPage() {
  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div>
        <h1 className="text-xl font-bold text-white">Security Analytics</h1>
        <p className="text-sm text-gray-500">7-day threat and traffic overview</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Weekly threats/bans */}
        <div className="card">
          <h3 className="text-sm font-semibold text-white mb-4">Weekly Threats & Bans</h3>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={MOCK_DAILY}>
              <CartesianGrid strokeDasharray="3 3" stroke="#253047" />
              <XAxis dataKey="day" tick={{ fontSize: 11, fill: "#6b7280" }} />
              <YAxis tick={{ fontSize: 11, fill: "#6b7280" }} />
              <Tooltip contentStyle={{ background: "#1a2035", border: "1px solid #253047", borderRadius: "8px", color: "#fff", fontSize: "12px" }} />
              <Bar dataKey="threats" fill="#ff4444" name="Threats" radius={[2, 2, 0, 0]} />
              <Bar dataKey="bans" fill="#3b82f6" name="Bans" radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Threat type distribution */}
        <div className="card">
          <h3 className="text-sm font-semibold text-white mb-4">Threat Distribution</h3>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={MOCK_THREAT_TYPES} cx="50%" cy="50%" innerRadius={50} outerRadius={80} dataKey="value" paddingAngle={3}>
                {MOCK_THREAT_TYPES.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: "#1a2035", border: "1px solid #253047", borderRadius: "8px", color: "#fff", fontSize: "12px" }} />
              <Legend formatter={(value) => <span style={{ color: "#9ca3af", fontSize: "12px" }}>{value}</span>} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Connection volume */}
        <div className="card lg:col-span-2">
          <h3 className="text-sm font-semibold text-white mb-4">Connection Volume</h3>
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={MOCK_DAILY}>
              <CartesianGrid strokeDasharray="3 3" stroke="#253047" />
              <XAxis dataKey="day" tick={{ fontSize: 11, fill: "#6b7280" }} />
              <YAxis tick={{ fontSize: 11, fill: "#6b7280" }} />
              <Tooltip contentStyle={{ background: "#1a2035", border: "1px solid #253047", borderRadius: "8px", color: "#fff", fontSize: "12px" }} />
              <Line type="monotone" dataKey="connections" stroke="#0066ff" strokeWidth={2} dot={false} name="Connections" />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
