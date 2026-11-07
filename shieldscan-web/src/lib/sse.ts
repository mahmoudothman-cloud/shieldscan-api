/**
 * Server-Sent Events over `fetch`.
 *
 * The native EventSource cannot send an Authorization header, and the
 * session cookie is scoped to /v1/auth on purpose, so the progress
 * stream is read with fetch + a ReadableStream parser. Supports
 * `Last-Event-ID` ("-" replays the whole stream), `event:`/`data:`/
 * `id:` fields, multi-line data, and comment pings.
 */

import { getAccessToken, refreshSession } from "./api";

export interface SseMessage {
  id: string | null;
  event: string;
  data: string;
}

export interface SseOptions {
  lastEventId?: string;
  signal: AbortSignal;
  onMessage: (m: SseMessage) => void;
  onOpen?: () => void;
  onError?: (err: unknown) => void;
}

export async function readSse(url: string, opts: SseOptions): Promise<void> {
  const headers: Record<string, string> = { Accept: "text/event-stream" };
  if (opts.lastEventId) headers["Last-Event-ID"] = opts.lastEventId;
  const token = getAccessToken();
  if (token) headers.Authorization = `Bearer ${token}`;

  let res: Response;
  try {
    res = await fetch(url, { headers, signal: opts.signal, credentials: "include" });
    if (res.status === 401 && (await refreshSession())) {
      headers.Authorization = `Bearer ${getAccessToken() ?? ""}`;
      res = await fetch(url, { headers, signal: opts.signal, credentials: "include" });
    }
  } catch (err) {
    if (!opts.signal.aborted) opts.onError?.(err);
    return;
  }
  if (!res.ok || !res.body) {
    opts.onError?.(new Error(`SSE HTTP ${res.status}`));
    return;
  }
  opts.onOpen?.();

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let id: string | null = null;
  let event = "message";
  let data: string[] = [];

  const flush = () => {
    if (data.length > 0) opts.onMessage({ id, event, data: data.join("\n") });
    event = "message";
    data = [];
  };

  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let nl: number;
      while ((nl = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, nl).replace(/\r$/, "");
        buffer = buffer.slice(nl + 1);
        if (line === "") {
          flush();
          continue;
        }
        if (line.startsWith(":")) continue; // ping / comment
        const colon = line.indexOf(":");
        const field = colon < 0 ? line : line.slice(0, colon);
        const value = colon < 0 ? "" : line.slice(colon + 1).replace(/^ /, "");
        if (field === "event") event = value;
        else if (field === "data") data.push(value);
        else if (field === "id") id = value;
      }
    }
    flush();
  } catch (err) {
    if (!opts.signal.aborted) opts.onError?.(err);
  }
}
