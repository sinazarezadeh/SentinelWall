import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Server, CheckCircle, ChevronRight } from "lucide-react";
import toast from "react-hot-toast";
import { profilesApi } from "../api/client";

export default function ProfilesPage() {
  const qc = useQueryClient();

  const { data: profilesData } = useQuery({
    queryKey: ["profiles"],
    queryFn: () => profilesApi.list().then((r) => r.data),
  });

  const applyProfile = useMutation({
    mutationFn: (name: string) => profilesApi.apply(name),
    onSuccess: (_, name) => {
      toast.success(`Profile '${name}' applied`);
      qc.invalidateQueries({ queryKey: ["rules"] });
    },
    onError: () => toast.error("Failed to apply profile"),
  });

  const profiles = profilesData?.data ?? [];

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div>
        <h1 className="text-xl font-bold text-white">Firewall Profiles</h1>
        <p className="text-sm text-gray-500">Pre-built rule sets for common deployments</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {profiles.map((profile: any) => (
          <div key={profile.name} className="card hover:border-sentinel-600/50 transition-colors group">
            <div className="flex items-start justify-between mb-3">
              <div className="p-2 bg-sentinel-600/10 rounded-lg border border-sentinel-600/20">
                <Server className="w-5 h-5 text-sentinel-400" />
              </div>
              <button
                onClick={() => {
                  if (confirm(`Apply profile '${profile.name}'? This will add ${profile.name} rules.`)) {
                    applyProfile.mutate(profile.name);
                  }
                }}
                disabled={applyProfile.isPending}
                className="opacity-0 group-hover:opacity-100 transition-opacity btn-primary text-xs py-1 px-3"
              >
                Apply
              </button>
            </div>
            <h3 className="font-semibold text-white capitalize">
              {profile.name.replace(/-/g, " ")}
            </h3>
            <p className="text-sm text-gray-500 mt-1">{profile.description}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
