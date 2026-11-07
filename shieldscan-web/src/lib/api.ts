/**
 * HTTP client for the ShieldScan API.
 *
 * Session model (CONSTITUTION §14.2, no localStorage):
 * - the REFRESH token lives in the `shieldscan_refresh` httpOnly cookie
 *   (path /v1/auth) that the API sets on login/refresh — JS never sees it;
 * - the ACCESS token (15 min) is kept here, in module memory only. A page
 *   reload loses it, and `bootstrapSession()` gets a new one with a
 *   cookie-only POST /v1/auth/refresh.
 *
 * On a 401 from any authenticated call the client refreshes once and
 * retries; if the refresh fails too the session is gone and
 * `onSessionLost` fires (the AuthProvider routes to /login).
 *
 * All components go through TanStack Query hooks (lib/queries.ts); this
 * module is the one place that talks to `fetch`.
 */

export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;
  constructor(status: number, detail: unknown, message?: string) {
    super(message ?? (typeof detail === "string" ? detail : `HTTP ${status}`));
    this.status = status;
    this.detail = detail;
  }
}

let accessToken: string | null = null;
let refreshInFlight: Promise<boolean> | null = null;
let sessionLostHandler: (() => void) | null = null;

export function setAccessToken(token: string | null): void {
  accessToken = token;
}
export function getAccessToken(): string | null {
  return accessToken;
}
export function onSessionLost(handler: (() => void) | null): void {
  sessionLostHandler = handler;
}

export interface UserResponse {
  id: string;
  email: string;
  full_name: string;
  email_verified: boolean;
}
export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: UserResponse;
}

async function parseBody(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

function detailOf(body: unknown): unknown {
  if (body && typeof body === "object" && "detail" in body) {
    return (body as { detail: unknown }).detail;
  }
  return body;
}

/** Cookie-only refresh. Resolves true when a new access token is in memory. */
export async function refreshSession(): Promise<boolean> {
  if (refreshInFlight) return refreshInFlight;
  refreshInFlight = (async () => {
    try {
      const res = await fetch("/v1/auth/refresh", {
        method: "POST",
        credentials: "include",
        headers: { Accept: "application/json" },
      });
      if (!res.ok) {
        accessToken = null;
        return false;
      }
      const body = (await res.json()) as TokenResponse;
      accessToken = body.access_token;
      return true;
    } catch {
      accessToken = null;
      return false;
    } finally {
      refreshInFlight = null;
    }
  })();
  return refreshInFlight;
}

export interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
  body?: unknown;
  /** Skip the Authorization header and the 401→refresh dance (public + auth routes). */
  anonymous?: boolean;
  signal?: AbortSignal;
}

export async function api<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const doFetch = async (): Promise<Response> => {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    if (!opts.anonymous && accessToken) headers.Authorization = `Bearer ${accessToken}`;
    const init: RequestInit = {
      method: opts.method ?? "GET",
      headers,
      credentials: "include",
    };
    if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
    if (opts.signal) init.signal = opts.signal;
    return fetch(path, init);
  };

  let res = await doFetch();
  if (res.status === 401 && !opts.anonymous) {
    const ok = await refreshSession();
    if (ok) {
      res = await doFetch();
    } else {
      sessionLostHandler?.();
    }
  }
  const body = await parseBody(res);
  if (!res.ok) throw new ApiError(res.status, detailOf(body));
  return body as T;
}

/** Login: body tokens for memory, cookie set by the server for the refresh. */
export async function login(email: string, password: string): Promise<TokenResponse> {
  const tokens = await api<TokenResponse>("/v1/auth/login", {
    method: "POST",
    body: { email, password },
    anonymous: true,
  });
  accessToken = tokens.access_token;
  return tokens;
}

export async function logout(): Promise<void> {
  try {
    await api<null>("/v1/auth/logout", { method: "POST" });
  } finally {
    accessToken = null;
  }
}
