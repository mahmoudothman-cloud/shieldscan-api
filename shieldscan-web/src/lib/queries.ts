/**
 * TanStack Query hooks — the only way components reach the API
 * (CONSTITUTION §13.4). Keys are arrays rooted at the org so a sign-out
 * (`queryClient.clear()`) or an org switch drops everything at once.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import type {
  SubscriptionView,
  AdminOrgDetail,
  AdminOrgList,
  AdminOverride,
  AdminPlanList,
  AdminVersionInput,
  AdminVersionPublished,
  BillingSummaryResponse,
  PlanCatalogResponse,
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
  EvidenceItem,
  FixResponse,
  PaginatedVulnerabilitiesResponse,
  VulnerabilityDetail,
  VulnerabilityHistoryItem,
  VulnerabilityStatus,
  APIKeyCreatedResponse,
  APIKeySummary,
  MemberInviteResponse,
  MemberItem,
  OrgPatchInput,
  ExecutiveReportResponse,
  PdfReportResponse,
  ReportManifest,
  PublicScanCreateResponse,
  PublicScanResult,
  FrameworkCatalog,
  OrgPostureResponse,
  ToolHealthResponse,
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

// ---------------------------------------------------------------- vulnerabilities

export interface VulnFilters {
  page?: number;
  per_page?: number;
  sort?: string;
  severity?: string;
  status?: string;
  engine_category?: string;
  scan_id?: string;
  project_id?: string;
}

function clean(params: VulnFilters): Record<string, string | number> {
  const out: Record<string, string | number> = {};
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== "") out[k] = v;
  return out;
}

export function useVulnerabilities(orgId: string, filters: VulnFilters) {
  const p = clean({ page: 1, per_page: 25, sort: "-severity_score", ...filters });
  return useQuery({
    queryKey: [...keys.org(orgId), "vulnerabilities", p] as const,
    queryFn: () =>
      api<PaginatedVulnerabilitiesResponse>(`/v1/orgs/${orgId}/vulnerabilities${qs(p)}`),
    placeholderData: (prev) => prev,
  });
}

export function useVulnerability(orgId: string, vid: string) {
  return useQuery({
    queryKey: [...keys.org(orgId), "vulnerability", vid] as const,
    queryFn: () => api<VulnerabilityDetail>(`/v1/orgs/${orgId}/vulnerabilities/${vid}`),
  });
}

export function useVulnerabilityEvidence(orgId: string, vid: string) {
  return useQuery({
    queryKey: [...keys.org(orgId), "vulnerability", vid, "evidence"] as const,
    queryFn: () => api<EvidenceItem[]>(`/v1/orgs/${orgId}/vulnerabilities/${vid}/evidence`),
  });
}

export function useVulnerabilityFix(orgId: string, vid: string) {
  return useQuery({
    queryKey: [...keys.org(orgId), "vulnerability", vid, "fix"] as const,
    queryFn: () => api<FixResponse>(`/v1/orgs/${orgId}/vulnerabilities/${vid}/fix`),
  });
}

export function useVulnerabilityHistory(orgId: string, vid: string) {
  return useQuery({
    queryKey: [...keys.org(orgId), "vulnerability", vid, "history"] as const,
    queryFn: () =>
      api<VulnerabilityHistoryItem[]>(`/v1/orgs/${orgId}/vulnerabilities/${vid}/history`),
  });
}

export function useUpdateVulnerabilityStatus(orgId: string, vid: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: { status: VulnerabilityStatus; notes?: string }) =>
      api<VulnerabilityDetail>(`/v1/orgs/${orgId}/vulnerabilities/${vid}`, {
        method: "PATCH",
        body: input,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.org(orgId) }),
  });
}

// ---------------------------------------------------------------- settings: org, members, API keys

export function useUpdateOrg(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: OrgPatchInput) =>
      api<OrgResponse>(`/v1/orgs/${orgId}`, { method: "PATCH", body: input }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.org(orgId) });
      void qc.invalidateQueries({ queryKey: ["auth", "me"] });
    },
  });
}

export function useMembers(orgId: string) {
  return useQuery({
    queryKey: [...keys.org(orgId), "members"] as const,
    queryFn: () => api<MemberItem[]>(`/v1/orgs/${orgId}/members`),
  });
}

export function useInviteMember(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: { email: string; role: MemberItem["role"]; full_name?: string }) =>
      api<MemberInviteResponse>(`/v1/orgs/${orgId}/members`, { method: "POST", body: input }),
    onSuccess: () => qc.invalidateQueries({ queryKey: [...keys.org(orgId), "members"] }),
  });
}

export function useChangeMemberRole(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: { userId: string; role: MemberItem["role"] }) =>
      api<MemberItem>(`/v1/orgs/${orgId}/members/${input.userId}`, {
        method: "PATCH",
        body: { role: input.role },
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.org(orgId) }),
  });
}

export function useRemoveMember(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (userId: string) =>
      api<null>(`/v1/orgs/${orgId}/members/${userId}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.org(orgId) }),
  });
}

export const API_KEYS_KEY = ["auth", "api-keys"] as const;

export function useApiKeys() {
  return useQuery({
    queryKey: API_KEYS_KEY,
    queryFn: () => api<APIKeySummary[]>("/v1/auth/api-keys"),
  });
}

export function useCreateApiKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) =>
      api<APIKeyCreatedResponse>("/v1/auth/api-keys", { method: "POST", body: { name } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: API_KEYS_KEY }),
  });
}

export function useRevokeApiKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (keyId: string) => api<null>(`/v1/auth/api-keys/${keyId}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: API_KEYS_KEY }),
  });
}

// ---------------------------------------------------------------- reports

export function useReportManifest(orgId: string, scanId: string) {
  return useQuery({
    queryKey: [...keys.org(orgId), "scan", scanId, "report"] as const,
    queryFn: () => api<ReportManifest>(`/v1/orgs/${orgId}/scans/${scanId}/report`),
    retry: false,
  });
}

export function useExecutiveReport(orgId: string, scanId: string, enabled: boolean) {
  return useQuery({
    queryKey: [...keys.org(orgId), "scan", scanId, "report", "executive"] as const,
    queryFn: () =>
      api<ExecutiveReportResponse>(`/v1/orgs/${orgId}/scans/${scanId}/report/executive`),
    enabled,
    retry: false,
  });
}

/** PDF is generated on first request and stored; the response is a short-lived signed URL. */
export function useRequestPdf(orgId: string, scanId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api<PdfReportResponse>(`/v1/orgs/${orgId}/scans/${scanId}/report/pdf`),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: [...keys.org(orgId), "scan", scanId, "report"] }),
  });
}

/** SARIF / JSON are rendered inline by the API; fetch and hand to the browser as a file. */
export function useDownloadInline(orgId: string, scanId: string) {
  return useMutation({
    mutationFn: async (format: "sarif" | "json") => {
      const body = await api<unknown>(`/v1/orgs/${orgId}/scans/${scanId}/report/${format}`);
      const blob = new Blob([JSON.stringify(body, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `shieldscan-${scanId.slice(0, 8)}.${format === "sarif" ? "sarif.json" : "json"}`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
    },
  });
}

// ---------------------------------------------------------------- public quick scan (anonymous)

export function useCreateQuickScan() {
  return useMutation({
    mutationFn: (input: { target_url: string; email: string; consent: true }) =>
      api<PublicScanCreateResponse>("/v1/public/quick-scans", {
        method: "POST",
        body: input,
        anonymous: true,
      }),
  });
}

export function useQuickScanResult(slug: string) {
  return useQuery({
    queryKey: ["public", "quick-scan", slug] as const,
    queryFn: () => api<PublicScanResult>(`/v1/public/quick-scans/${slug}`, { anonymous: true }),
    retry: false,
    refetchInterval: (q) =>
      q.state.data && ACTIVE_STATUSES.includes(q.state.data.status) ? 4_000 : false,
  });
}

// ---------------------------------------------------------------- compliance + tool health

export function useOrgPosture(orgId: string) {
  return useQuery({
    queryKey: [...keys.org(orgId), "compliance", "posture"] as const,
    queryFn: () => api<OrgPostureResponse>(`/v1/orgs/${orgId}/compliance/posture`),
  });
}

export function useFrameworkCatalog(orgId: string) {
  return useQuery({
    queryKey: [...keys.org(orgId), "compliance", "frameworks"] as const,
    queryFn: () => api<FrameworkCatalog>(`/v1/orgs/${orgId}/compliance/frameworks`),
    staleTime: 60 * 60_000,
  });
}

export function useToolHealth(orgId: string) {
  return useQuery({
    queryKey: [...keys.org(orgId), "tools", "health"] as const,
    queryFn: () => api<ToolHealthResponse>(`/v1/orgs/${orgId}/tools/health`),
    refetchInterval: 30_000,
  });
}

// ---------------------------------------------------------------- plans & billing (M12)

export function usePlans() {
  return useQuery({
    queryKey: ["plans"] as const,
    queryFn: () => api<PlanCatalogResponse>("/v1/plans", { anonymous: true }),
    staleTime: 5 * 60_000,
  });
}

export function useBillingSummary(orgId: string) {
  return useQuery({
    queryKey: [...keys.org(orgId), "billing"] as const,
    queryFn: () => api<BillingSummaryResponse>(`/v1/orgs/${orgId}/billing/summary`),
  });
}

// ---------------------------------------------------------------- platform admin (M12 slice 3)

export const adminKeys = {
  plans: ["admin", "plans"] as const,
  orgs: (q: string) => ["admin", "orgs", q] as const,
  org: (id: string) => ["admin", "org", id] as const,
};

export function useAdminPlans() {
  return useQuery({
    queryKey: adminKeys.plans,
    queryFn: () => api<AdminPlanList>("/v1/admin/plans"),
  });
}

export function usePublishPlanVersion(code: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: AdminVersionInput) =>
      api<AdminVersionPublished>(`/v1/admin/plans/${code}/versions`, {
        method: "POST",
        body: input,
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: adminKeys.plans });
      void qc.invalidateQueries({ queryKey: ["plans"] });
    },
  });
}

export function usePatchPlan(code: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: {
      is_public?: boolean;
      archived?: boolean;
      name?: string;
      rank?: number;
    }) => api(`/v1/admin/plans/${code}`, { method: "PATCH", body: input }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: adminKeys.plans });
      void qc.invalidateQueries({ queryKey: ["plans"] });
    },
  });
}

export function useAdminOrgs(q: string) {
  return useQuery({
    queryKey: adminKeys.orgs(q),
    queryFn: () => api<AdminOrgList>(`/v1/admin/orgs?q=${encodeURIComponent(q)}&limit=50`),
  });
}

export function useAdminOrg(id: string | null) {
  return useQuery({
    queryKey: adminKeys.org(id ?? ""),
    queryFn: () => api<AdminOrgDetail>(`/v1/admin/orgs/${id}`),
    enabled: id !== null,
  });
}

export function useSetOverride(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: {
      key: string;
      value: unknown;
      reason?: string;
      expires_at?: string | null;
    }) =>
      api<AdminOverride>(`/v1/admin/orgs/${orgId}/overrides/${input.key}`, {
        method: "PUT",
        body: { value: input.value, reason: input.reason, expires_at: input.expires_at ?? null },
      }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: adminKeys.org(orgId) }),
  });
}

export function useRemoveOverride(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (key: string) =>
      api<null>(`/v1/admin/orgs/${orgId}/overrides/${key}`, { method: "DELETE" }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: adminKeys.org(orgId) }),
  });
}

export function useAssignSubscription(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: { plan_code: string; billing_interval: "month" | "year"; note?: string }) =>
      api(`/v1/admin/orgs/${orgId}/subscription`, { method: "POST", body: input }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: adminKeys.org(orgId) });
      void qc.invalidateQueries({ queryKey: ["admin", "orgs"] });
    },
  });
}

// ---------------------------------------------------------------- billing (M12 slice 4)

export function useSubscription(orgId: string) {
  return useQuery({
    queryKey: [...keys.org(orgId), "subscription"] as const,
    queryFn: () => api<SubscriptionView>(`/v1/orgs/${orgId}/billing/subscription`),
  });
}

export function useStartCheckout(orgId: string) {
  return useMutation({
    mutationFn: (input: { plan_code: string; billing_interval: "month" | "year" }) =>
      api<{ subscription_id: string; checkout_url: string }>(`/v1/orgs/${orgId}/billing/checkout`, {
        method: "POST",
        body: input,
      }),
  });
}

export function useCancelSubscription(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api<SubscriptionView>(`/v1/orgs/${orgId}/billing/cancel`, { method: "POST" }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.org(orgId) });
    },
  });
}
