import { useEffect, useRef, useState } from "react";
import { WS_URL, type StreamMessage } from "./api";

export type StreamStatus = "connecting" | "open" | "closed";

/** Subscribe to WS /v1/stream. Reconnects with capped exponential backoff; pings to survive idle proxies. */
export function useStream(onMessage: (msg: StreamMessage) => void): StreamStatus {
  const [status, setStatus] = useState<StreamStatus>("connecting");
  const handler = useRef(onMessage);
  handler.current = onMessage;

  useEffect(() => {
    let ws: WebSocket | null = null;
    let retry = 0;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let pingTimer: ReturnType<typeof setInterval> | undefined;
    let stopped = false;

    const connect = () => {
      setStatus("connecting");
      ws = new WebSocket(WS_URL);
      ws.onopen = () => {
        retry = 0;
        setStatus("open");
        pingTimer = setInterval(() => ws?.readyState === WebSocket.OPEN && ws.send("ping"), 25_000);
      };
      ws.onmessage = (e) => {
        try {
          handler.current(JSON.parse(e.data) as StreamMessage);
        } catch {
          // a malformed frame shouldn't take the console down
        }
      };
      ws.onclose = () => {
        clearInterval(pingTimer);
        if (stopped) return;
        setStatus("closed");
        retryTimer = setTimeout(connect, Math.min(10_000, 500 * 2 ** retry++));
      };
    };

    connect();
    return () => {
      stopped = true;
      clearTimeout(retryTimer);
      clearInterval(pingTimer);
      ws?.close();
    };
  }, []);

  return status;
}
