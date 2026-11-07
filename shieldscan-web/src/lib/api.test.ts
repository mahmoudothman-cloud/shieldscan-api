/**
 * The session contract: access token in memory only, cookie-driven
 * refresh on 401 with a single retry, and session-lost signalling when
 * the refresh itself fails.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  api,
  getAccessToken,
  login,
  onSessionLost,
  refreshSession,
  setAccessToken,
} from "./api";

type FetchMock = ReturnType<typeof vi.fn<typeof fetch>>;

function jsonResponse(status: number, body: unknown): Response {
  return new Response(body === null ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

let fetchMock: FetchMock;

beforeEach(() => {
  fetchMock = vi.fn<typeof fetch>();
  vi.stubGlobal("fetch", fetchMock);
  setAccessToken(null);
  onSessionLost(null);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("api()", () => {
  it("sends the bearer token and credentials, parses JSON", async () => {
    setAccessToken("tok");
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { ok: true }));
    const out = await api<{ ok: boolean }>("/v1/x");
    expect(out).toEqual({ ok: true });
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("/v1/x");
    expect(init?.credentials).toBe("include");
    expect((init?.headers as Record<string, string>).Authorization).toBe("Bearer tok");
  });

  it("on 401: refreshes from the cookie once, then retries with the new token", async () => {
    setAccessToken("stale");
    fetchMock
      .mockResolvedValueOnce(jsonResponse(401, { detail: "unauthorized" }))
      .mockResolvedValueOnce(
        jsonResponse(200, { access_token: "fresh", refresh_token: "r", user: {} }),
      )
      .mockResolvedValueOnce(jsonResponse(200, { ok: 1 }));
    const out = await api<{ ok: number }>("/v1/orgs/1/summary");
    expect(out).toEqual({ ok: 1 });
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls[1]![0]).toBe("/v1/auth/refresh");
    const retryHeaders = fetchMock.mock.calls[2]![1]?.headers as Record<string, string>;
    expect(retryHeaders.Authorization).toBe("Bearer fresh");
    expect(getAccessToken()).toBe("fresh");
  });

  it("on 401 with a failed refresh: clears the token, fires onSessionLost, throws ApiError 401", async () => {
    setAccessToken("stale");
    const lost = vi.fn();
    onSessionLost(lost);
    fetchMock
      .mockResolvedValueOnce(jsonResponse(401, { detail: "unauthorized" }))
      .mockResolvedValueOnce(jsonResponse(401, { detail: "unauthorized" }));
    await expect(api("/v1/orgs/1/summary")).rejects.toMatchObject({ status: 401 });
    expect(lost).toHaveBeenCalledTimes(1);
    expect(getAccessToken()).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("anonymous calls never refresh", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { detail: "unauthorized" }));
    await expect(
      api("/v1/auth/login", { anonymous: true, method: "POST", body: {} }),
    ).rejects.toBeInstanceOf(ApiError);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("concurrent 401s share one refresh", async () => {
    setAccessToken("stale");
    let resolveRefresh: (r: Response) => void = () => undefined;
    const refreshPromise = new Promise<Response>((res) => (resolveRefresh = res));
    fetchMock.mockImplementation((url) => {
      if (url === "/v1/auth/refresh") return refreshPromise;
      const auth = (fetchMock.mock.lastCall?.[1]?.headers as Record<string, string> | undefined)
        ?.Authorization;
      return Promise.resolve(
        auth === "Bearer fresh" ? jsonResponse(200, { ok: true }) : jsonResponse(401, {}),
      );
    });
    const a = api("/v1/a");
    const b = api("/v1/b");
    await Promise.resolve();
    resolveRefresh(jsonResponse(200, { access_token: "fresh", refresh_token: "r", user: {} }));
    await Promise.all([a, b]);
    const refreshCalls = fetchMock.mock.calls.filter((c) => c[0] === "/v1/auth/refresh");
    expect(refreshCalls).toHaveLength(1);
  });

  it("exposes the API detail on errors", async () => {
    setAccessToken("tok");
    fetchMock.mockResolvedValueOnce(jsonResponse(409, { detail: "last_admin" }));
    const err = await api("/v1/orgs/1/members/2", { method: "DELETE" }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).detail).toBe("last_admin");
    expect((err as ApiError).message).toBe("last_admin");
  });
});

describe("login() / refreshSession()", () => {
  it("login stores the access token from the body (the cookie is the server's job)", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, { access_token: "a1", refresh_token: "r1", user: { id: "u" } }),
    );
    const tokens = await login("a@b.co", "pw");
    expect(tokens.access_token).toBe("a1");
    expect(getAccessToken()).toBe("a1");
    const init = fetchMock.mock.calls[0]![1];
    expect(init?.credentials).toBe("include");
    expect(JSON.parse(init?.body as string)).toEqual({ email: "a@b.co", password: "pw" });
  });

  it("refreshSession posts with no body and resolves false on 401", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { detail: "unauthorized" }));
    expect(await refreshSession()).toBe(false);
    const init = fetchMock.mock.calls[0]![1];
    expect(init?.method).toBe("POST");
    expect(init?.body).toBeUndefined();
    expect(getAccessToken()).toBeNull();
  });
});
