import { Outlet, NavLink, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Shield, LayoutDashboard, ScrollText, Ban, AlertTriangle,
  BarChart3, Server, Users, Settings, LogOut, Wifi, WifiOff,
  ChevronRight
} from "lucide-react";
import { useAuthStore } from "../store/auth";
import { statusApi } from "../api/client";
import { useWebSocket } from "../hooks/useWebSocket";
import { clsx } from "clsx";

const navItems = [
  { to: "/dashboard", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/rules", icon: ScrollText, label: "Rules" },
  { to: "/bans", icon: Ban, label: "Bans" },
  { to: "/threats", icon: AlertTriangle, label: "Threats" },
  { to: "/analytics", icon: BarChart3, label: "Analytics" },
  { to: "/profiles", icon: Server, label: "Profiles" },
  { to: "/users", icon: Users, label: "Users" },
  { to: "/settings", icon: Settings, label: "Settings" },
];

export default function Layout() {
  const { user, logout } = useAuthStore();
  const navigate = useNavigate();

  const { data: status } = useQuery({
    queryKey: ["status"],
    queryFn: () => statusApi.get().then((r) => r.data),
    refetchInterval: 5000,
  });

  const { connected } = useWebSocket();

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <div className="flex h-screen bg-surface-primary overflow-hidden">
      {/* Sidebar */}
      <aside className="w-60 flex flex-col bg-surface-secondary border-r border-surface-border flex-shrink-0">
        {/* Logo */}
        <div className="px-4 py-5 border-b border-surface-border">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 bg-sentinel-600 rounded-lg flex items-center justify-center flex-shrink-0">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="font-bold text-white text-sm">SentinelWall</div>
              <div className="text-xs text-gray-500">Firewall Dashboard</div>
            </div>
          </div>
        </div>

        {/* Connection status */}
        <div className="px-4 py-2 border-b border-surface-border">
          <div className="flex items-center gap-2 text-xs">
            {connected ? (
              <>
                <div className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
                <span className="text-green-400">Live</span>
              </>
            ) : (
              <>
                <div className="w-1.5 h-1.5 rounded-full bg-red-400" />
                <span className="text-red-400">Disconnected</span>
              </>
            )}
            <span className="text-gray-600 ml-auto">
              v{status?.data?.version ?? "—"}
            </span>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-3 space-y-0.5 overflow-y-auto">
          {navItems.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                clsx(
                  "flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors",
                  isActive
                    ? "bg-sentinel-600/20 text-sentinel-400 border border-sentinel-600/30"
                    : "text-gray-400 hover:text-white hover:bg-surface-hover"
                )
              }
            >
              <Icon className="w-4 h-4" />
              {label}
            </NavLink>
          ))}
        </nav>

        {/* User section */}
        <div className="p-3 border-t border-surface-border">
          <div className="flex items-center gap-3 px-2 py-2">
            <div className="w-8 h-8 rounded-full bg-sentinel-600/30 border border-sentinel-600/50 flex items-center justify-center">
              <span className="text-xs text-sentinel-400 font-bold uppercase">
                {user?.username?.[0] ?? "?"}
              </span>
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium text-white truncate">{user?.username}</div>
              <div className="text-xs text-gray-500 capitalize">{user?.role}</div>
            </div>
            <button
              onClick={handleLogout}
              className="text-gray-500 hover:text-red-400 transition-colors"
              title="Logout"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
