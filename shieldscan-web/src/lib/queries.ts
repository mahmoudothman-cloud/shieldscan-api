/**
 * TanStack Query hooks — the only way components reach the API
 * (CONSTITUTION §13.4). Keys are arrays rooted at the org so a sign-out
 * (`queryClient.clear()`) or an org switch drops everything at once.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import type {
  OrgResponse,
  OrgSummaryResponse,
  PaginatedProjectsResponse,
  PaginatedScansResponse,
  ProjectCreateInput,
  ProjectResponse,
  ScanCreateInput,
  ScanDetailResponse,
  ScanResponse,
  VerifyDomainSuccess,
} from "./types";

export const keys = {
  org: (orgId: string) => ["org", orgId] as const,
  summary: (orgId: string) => ["org", orgId, "summary"] as const,
  scans: (orgId: string, params: Record<string, string | number>) =>
    ["org", orgId, "scans", params] as const,
  projects: (orgId: string, params: Record<string, string | number>) =>
    ["org", orgId, "projects", params] as const,
};

function qs(params: Record<string, string | number>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) sp.set(k, String(v));
  const s = sp.toString();
  return s ? `?${s}` : "";
}

export function useOrg(orgId: string) {
  return useQuery({
    queryKey: keys.org(orgId),
    queryFn: () => api<OrgResponse>(`/v1/orgs/${orgId}`),
    staleTime: 60_000,
  });
}

export function useOrgSummary(orgId: string) {
  return useQuery({
    queryKey: keys.summary(orgId),
    queryFn: () => api<OrgSummaryResponse>(`/v1/orgs/${orgId}/summary`),
    refetchInterval: (q) => (q.state.data && q.state.data.scans.active > 0 ? 10_000 : false),
  });
}

export function useOrgScans(orgId: string, params: { page?: number; per_page?: number } = {}) {
  const p = { page: params.page ?? 1, per_page: params.per_page ?? 10 };
  return useQuery({
    queryKey: keys.scans(orgId, p),
    queryFn: () => api<PaginatedScansResponse>(`/v1/orgs/${orgId}/scans${qs(p)}`),
    refetchInterval: (q) =>
      q.state.data?.items.some((s) =>
        ["queued", "reconning", "running", "analyzing"].includes(s.status),
      )
        ? 5_000
        : false,
  });
}

export function useProjects(orgId: string, params: { page?: number; per_page?: number } = {}) {
  const p = { page: params.page ?? 1, per_page: params.per_page ?? 50 };
  return useQuery({
    queryKey: keys.projects(orgId, p),
    queryFn: () => api<PaginatedProjectsResponse>(`/v1/orgs/${orgId}/projects${qs(p)}`),
    staleTime: 30_000,
  });
}

// ---------------------------------------------------------------- auth mutations (anonymous)

export interface RegisterInput {
  email: string;
  password: string;
  full_name: string;
  organization_name: string;
}

export function useRegister() {
  return useMutation({
    mutationFn: (input: RegisterInput) =>
      api<unknown>("/v1/auth/register", { method: "POST", body: input, anonymous: true }),
  });
}

export function useVerifyEmail() {
  return useMutation({
    mutationFn: (token: string) =>
      api<{ email_verified: boolean }>("/v1/auth/verify-email", {
        method: "POST",
        body: { token },
        anonymous: true,
      }),
  });
}

export function useResendVerification() {
  return useMutation({
    mutationFn: (email: string) =>
      api<unknown>("/v1/auth/resend-verification", {
        method: "POST",
        body: { email },
        anonymous: true,
      }),
  });
}

export function useForgotPassword() {
  return useMutation({
    mutationFn: (email: string) =>
      api<unknown>("/v1/auth/forgot-password", {
        method: "POST",
        body: { email },
        anonymous: true,
      }),
  });
}

export function useResetPassword() {
  return useMutation({
    mutationFn: (input: { token: string; new_password: string }) =>
      api<unknown>("/v1/auth/reset-password", { method: "POST", body: input, anonymous: true }),
  });
}

/** Invalidate everything under an org after a write. */
export function useInvalidateOrg(orgId: string) {
  const qc = useQueryClient();
  return () => qc.invalidateQueries({ queryKey: keys.org(orgId) });
}

// ---------------------------------------------------------------- projects

export function useProject(orgId: string, projectId: string) {
  return useQuery({
    queryKey: [...keys.org(orgId), "project", projectId] as const,
    queryFn: () => api<ProjectResponse>(`/v1/orgs/${orgId}/projects/${projectId}`),
  });
}

export function useCreateProject(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: ProjectCreateInput) =>
      api<ProjectResponse>(`/v1/orgs/${orgId}/projects`, { method: "POST", body: input }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.org(orgId) }),
  });
}

export function useArchiveProject(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (projectId: string) =>
      api<null>(`/v1/orgs/${orgId}/projects/${projectId}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.org(orgId) }),
  });
}

export function useVerifyDomain(orgId: string, projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (method: "dns_txt" | "meta_tag") =>
      api<VerifyDomainSuccess>(`/v1/orgs/${orgId}/projects/${projectId}/verify`, {
        method: "POST",
        body: { method },
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.org(orgId) }),
  });
}

export function useProjectScans(
  orgId: string,
  projectId: string,
  params: { page?: number; per_page?: number } = {},
) {
  const p = { page: params.page ?? 1, per_page: params.per_page ?? 10 };
  return useQuery({
    queryKey: [...keys.org(orgId), "project", projectId, "scans", p] as const,
    queryFn: () =>
      api<PaginatedScansResponse>(`/v1/orgs/${orgId}/projects/${projectId}/scans${qs(p)}`),
    refetchInterval: (q) =>
      q.state.data?.items.some((s) => ACTIVE_STATUSES.includes(s.status)) ? 5_000 : false,
  });
}

// ---------------------------------------------------------------- scans

export const ACTIVE_STATUSES: string[] = ["queued", "reconning", "running", "analyzing"];

export function useScan(orgId: string, scanId: string) {
  return useQuery({
    queryKey: [...keys.org(orgId), "scan", scanId] as const,
    queryFn: () => api<ScanDetailResponse>(`/v1/orgs/${orgId}/scans/${scanId}`),
    refetchInterval: (q) =>
      q.state.data && ACTIVE_STATUSES.includes(q.state.data.status) ? 4_000 : false,
  });
}

export function useCreateScan(orgId: string, projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: ScanCreateInput) =>
      api<ScanResponse>(`/v1/orgs/${orgId}/projects/${projectId}/scans`, {
        method: "POST",
        body: input,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.org(orgId) }),
  });
}

export function useCancelScan(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (scanId: string) =>
      api<null>(`/v1/orgs/${orgId}/scans/${scanId}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.org(orgId) }),
  });
}
