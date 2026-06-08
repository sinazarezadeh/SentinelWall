import { useEffect, useRef, useState, useCallback } from "react";
import { useAuthStore } from "../store/auth";

interface WSEvent {
  type: string;
  data: Record<string, unknown>;
}

interface UseWebSocketOptions {
  onEvent?: (event: WSEvent) => void;
  reconnectDelay?: number;
}

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const { token } = useAuthStore();
  const ws = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState<WSEvent[]>([]);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>();

  const connect = useCallback(() => {
    const wsUrl = `${window.location.protocol === "https:" ? "wss" : "ws"}://${window.location.host}/api/v1/ws`;

    const socket = new WebSocket(wsUrl);
    ws.current = socket;

    socket.onopen = () => {
      setConnected(true);
    };

    socket.onmessage = (e) => {
      try {
        const event: WSEvent = JSON.parse(e.data);
        setEvents((prev) => [event, ...prev.slice(0, 99)]);
        options.onEvent?.(event);
      } catch {}
    };

    socket.onclose = () => {
      setConnected(false);
      reconnectTimer.current = setTimeout(connect, options.reconnectDelay ?? 3000);
    };

    socket.onerror = () => {
      socket.close();
    };
  }, [token, options.reconnectDelay]);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimer.current);
      ws.current?.close();
    };
  }, [connect]);

  const send = useCallback((data: unknown) => {
    if (ws.current?.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify(data));
    }
  }, []);

  return { connected, events, send };
}
