import axios from "axios";
import { useAuthStore } from "../store/auth";

const API_BASE = import.meta.env.VITE_API_URL || "/api/v1";

export const api = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
});

api.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      useAuthStore.getState().logout();
      window.location.href = "/login";
    }
    return Promise.reject(error);
  }
);

// API functions
export const authApi = {
  login: (username: string, password: string) =>
    api.post("/auth/login", { username, password }),
  logout: () => api.post("/auth/logout"),
  me: () => api.get("/auth/me"),
};

export const statusApi = {
  get: () => api.get("/status"),
  info: () => api.get("/info"),
  metrics: () => api.get("/metrics"),
};

export const rulesApi = {
  list: () => api.get("/rules"),
  get: (id: string) => api.get(`/rules/${id}`),
  create: (rule: any) => api.post("/rules", rule),
  update: (id: string, rule: any) => api.put(`/rules/${id}`, rule),
  delete: (id: string) => api.delete(`/rules/${id}`),
  flush: () => api.post("/rules/flush"),
  export: () => api.get("/rules/export"),
  import: (rules: any[]) => api.post("/rules/import", rules),
};

export const bansApi = {
  list: () => api.get("/bans"),
  ban: (ip: string, reason: string, duration?: number, permanent?: boolean) =>
    api.post("/bans", { ip, reason, duration_secs: duration, permanent }),
  unban: (ip: string) => api.delete(`/bans/${ip}`),
  check: (ip: string) => api.get(`/bans/check/${ip}`),
};

export const profilesApi = {
  list: () => api.get("/profiles"),
  apply: (name: string) => api.post(`/profiles/${name}/apply`),
};

export const threatsApi = {
  list: () => api.get("/threats"),
  stats: () => api.get("/threats/stats"),
};

export const geoApi = {
  lookup: (ip: string) => api.get(`/geo/lookup/${ip}`),
};

export const usersApi = {
  list: () => api.get("/users"),
  create: (data: any) => api.post("/users", data),
  delete: (id: string) => api.delete(`/users/${id}`),
};

export const tokensApi = {
  list: () => api.get("/tokens"),
  create: (data: any) => api.post("/tokens", data),
  revoke: (id: string) => api.delete(`/tokens/${id}`),
};
