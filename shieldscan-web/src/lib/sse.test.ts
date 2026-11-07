/** SSE-over-fetch parser: fields, multi-line data, pings, Last-Event-ID, 401 refresh. */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readSse } from "./sse";
import { setAccessToken } from "./api";

function streamOf(chunks: string[]): Response {
  const enc = new TextEncoder();
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const c of chunks) controller.enqueue(enc.encode(c));
      controller.close();
    },
  });
  return new Response(body, { status: 200, headers: { "Content-Type": "text/event-stream" } });
}

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;
beforeEach(() => {
  fetchMock = vi.fn<typeof fetch>();
  vi.stubGlobal("fetch", fetchMock);
  setAccessToken("tok");
});
afterEach(() => vi.unstubAllGlobals());

describe("readSse", () => {
  it("parses id/event/data frames, joins multi-line data, ignores pings, splits across chunks", async () => {
    fetchMock.mockResolvedValueOnce(
      streamOf([
        ": ping\n\n",
        'id: 1-0\nevent: job_started\ndata: {"a":1}\n\n',
        "id: 2-0\ndata: line1\nda",
        "ta: line2\n\nevent: x\ndata: tail\n\n",
      ]),
    );
    const got: unknown[] = [];
    await readSse("/v1/orgs/o/scans/s/progress", {
      lastEventId: "-",
      signal: new AbortController().signal,
      onMessage: (m) => got.push(m),
    });
    expect(got).toEqual([
      { id: "1-0", event: "job_started", data: '{"a":1}' },
      { id: "2-0", event: "message", data: "line1\nline2" },
      { id: "2-0", event: "x", data: "tail" },
    ]);
    const headers = fetchMock.mock.calls[0]![1]?.headers as Record<string, string>;
    expect(headers["Last-Event-ID"]).toBe("-");
    expect(headers.Authorization).toBe("Bearer tok");
    expect(headers.Accept).toBe("text/event-stream");
  });

  it("refreshes once on 401 and reconnects with the new token", async () => {
    fetchMock
      .mockResolvedValueOnce(new Response(null, { status: 401 }))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "fresh", refresh_token: "r", user: {} }), {
          status: 200,
        }),
      )
      .mockResolvedValueOnce(streamOf(["data: ok\n\n"]));
    const got: string[] = [];
    await readSse("/v1/x", {
      signal: new AbortController().signal,
      onMessage: (m) => got.push(m.data),
    });
    expect(got).toEqual(["ok"]);
    expect(fetchMock.mock.calls[1]![0]).toBe("/v1/auth/refresh");
    expect((fetchMock.mock.calls[2]![1]?.headers as Record<string, string>).Authorization).toBe(
      "Bearer fresh",
    );
  });

  it("reports non-OK responses through onError and does not throw", async () => {
    fetchMock.mockResolvedValueOnce(new Response("nope", { status: 404 }));
    const onError = vi.fn();
    await readSse("/v1/x", {
      signal: new AbortController().signal,
      onMessage: () => undefined,
      onError,
    });
    expect(onError).toHaveBeenCalledTimes(1);
  });
});
