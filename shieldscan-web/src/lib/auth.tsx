/**
 * Session state for the app: who is signed in and which organization
 * they act in. Backed by GET /v1/auth/me through TanStack Query; the
 * access token itself lives in lib/api.ts.
 *
 * Boot sequence: `bootstrap` tries a cookie-only refresh once. If it
 * succeeds, /me loads and the app renders; if not, the user is sent to
 * /login (with `next` so they land where they were going).
 */

/* eslint-disable react-refresh/only-export-components -- provider + hooks live together by design */
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  api,
  getAccessToken,
  login as apiLogin,
  logout as apiLogout,
  onSessionLost,
  refreshSession,
} from "./api";
import type { MeResponse } from "./types";

export type AuthStatus = "booting" | "anonymous" | "authenticated";

interface AuthContextValue {
  status: AuthStatus;
  me: MeResponse | null;
  orgId: string | null;
  signIn: (email: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export const ME_QUERY_KEY = ["auth", "me"] as const;

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [booted, setBooted] = useState(false);
  const [hasToken, setHasToken] = useState<boolean>(() => getAccessToken() !== null);

  // One cookie-only refresh at startup.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      if (getAccessToken() === null) await refreshSession();
      if (!cancelled) {
        setHasToken(getAccessToken() !== null);
        setBooted(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // A failed in-flight refresh anywhere in the app ends the session.
  useEffect(() => {
    onSessionLost(() => {
      setHasToken(false);
      queryClient.removeQueries({ queryKey: ME_QUERY_KEY });
    });
    return () => onSessionLost(null);
  }, [queryClient]);

  const meQuery = useQuery({
    queryKey: ME_QUERY_KEY,
    queryFn: () => api<MeResponse>("/v1/auth/me"),
    enabled: booted && hasToken,
    staleTime: 5 * 60_000,
    retry: false,
  });

  const signIn = useCallback(
    async (email: string, password: string) => {
      await apiLogin(email, password);
      setHasToken(true);
      await queryClient.invalidateQueries({ queryKey: ME_QUERY_KEY });
    },
    [queryClient],
  );

  const signOut = useCallback(async () => {
    await apiLogout();
    setHasToken(false);
    queryClient.clear();
  }, [queryClient]);

  const status: AuthStatus = !booted
    ? "booting"
    : !hasToken
      ? "anonymous"
      : meQuery.isPending
        ? "booting"
        : meQuery.isError
          ? "anonymous"
          : "authenticated";

  const value = useMemo<AuthContextValue>(
    () => ({
      status,
      me: status === "authenticated" ? (meQuery.data ?? null) : null,
      orgId: status === "authenticated" ? (meQuery.data?.organization.id ?? null) : null,
      signIn,
      signOut,
    }),
    [status, meQuery.data, signIn, signOut],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}

/** For pages that are only rendered under RequireAuth: orgId is guaranteed. */
export function useOrgId(): string {
  const { orgId } = useAuth();
  if (!orgId) throw new Error("useOrgId called outside an authenticated route");
  return orgId;
}
