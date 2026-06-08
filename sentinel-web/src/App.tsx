import { Routes, Route, Navigate } from "react-router-dom";
import { useAuthStore } from "./store/auth";
import Layout from "./components/Layout";
import LoginPage from "./pages/Login";
import DashboardPage from "./pages/Dashboard";
import RulesPage from "./pages/Rules";
import BansPage from "./pages/Bans";
import ThreatsPage from "./pages/Threats";
import AnalyticsPage from "./pages/Analytics";
import ProfilesPage from "./pages/Profiles";
import SettingsPage from "./pages/Settings";
import UsersPage from "./pages/Users";

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuthStore();
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="rules" element={<RulesPage />} />
        <Route path="bans" element={<BansPage />} />
        <Route path="threats" element={<ThreatsPage />} />
        <Route path="analytics" element={<AnalyticsPage />} />
        <Route path="profiles" element={<ProfilesPage />} />
        <Route path="users" element={<UsersPage />} />
        <Route path="settings" element={<SettingsPage />} />
      </Route>
    </Routes>
  );
}
