import { Settings, Server, Shield, Bell, Key, Database } from "lucide-react";

export default function SettingsPage() {
  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div>
        <h1 className="text-xl font-bold text-white">Settings</h1>
        <p className="text-sm text-gray-500">Configure SentinelWall behavior</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {[
          { icon: Server, title: "Backend", desc: "nftables / iptables configuration" },
          { icon: Shield, title: "Detection", desc: "Threat detection thresholds" },
          { icon: Bell, title: "Notifications", desc: "Webhook and email alerts" },
          { icon: Key, title: "API Keys", desc: "Manage API tokens" },
          { icon: Database, title: "Storage", desc: "Database and log settings" },
          { icon: Settings, title: "General", desc: "Daemon and system settings" },
        ].map(({ icon: Icon, title, desc }) => (
          <div key={title} className="card hover:border-sentinel-600/50 transition-colors cursor-pointer group">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-sentinel-600/10 border border-sentinel-600/20 rounded-lg">
                <Icon className="w-5 h-5 text-sentinel-400" />
              </div>
              <div>
                <h3 className="font-medium text-white">{title}</h3>
                <p className="text-xs text-gray-500">{desc}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="card">
        <h3 className="text-sm font-semibold text-white mb-4">About SentinelWall</h3>
        <dl className="space-y-2 text-sm">
          <div className="flex justify-between">
            <dt className="text-gray-500">Version</dt>
            <dd className="text-white font-mono">0.1.0</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-gray-500">Backend</dt>
            <dd className="text-white">nftables</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-gray-500">License</dt>
            <dd className="text-white">MIT</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-gray-500">Repository</dt>
            <dd className="text-blue-400">github.com/sinazarezadeh/SentinelWall</dd>
          </div>
        </dl>
      </div>
    </div>
  );
}
