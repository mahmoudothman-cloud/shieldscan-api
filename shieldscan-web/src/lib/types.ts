/**
 * Wire types for the ShieldScan API responses the app consumes.
 * Field names mirror the Pydantic schemas (snake_case) on purpose: a
 * mismatch is then a visible diff against the API repo, not a mapping
 * bug hidden in a transform layer.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ScanStatus =
  | "queued"
  | "reconning"
  | "running"
  | "analyzing"
  | "completed"
  | "partial"
  | "failed"
  | "canceled";

export interface OrganizationSummary {
  id: string;
  name: string;
  slug: string;
}

export interface MeResponse {
  kind: "jwt" | "api_key";
  user: {
    id: string;
    email: string;
    full_name: string;
    email_verified: boolean;
    is_platform_admin?: boolean;
  } | null;
  organization: OrganizationSummary;
}

export interface OrgResponse {
  id: string;
  name: string;
  slug: string;
  industry: string | null;
  country: string | null;
  company_size: string | null;
  created_at: string;
  member_count: number;
  my_role: "admin" | "member" | "viewer" | null;
}

export interface OrgSummaryResponse {
  organization_id: string;
  projects: { total: number; verified: number; unverified: number };
  scans: { total: number; active: number; completed_30d: number };
  open_vulnerabilities: Record<Severity, number> & { total: number; corroborated: number };
  last_completed_scan: {
    id: string;
    project_id: string;
    project_name: string;
    status: ScanStatus;
    completed_at: string | null;
    raw_finding_count: number;
    vulnerability_count: number;
  } | null;
}

export interface ScanListItem {
  id: string;
  project_id: string;
  project_name: string;
  scan_type: string;
  status: ScanStatus;
  priority: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  jobs_total: number;
  jobs_terminal: number;
  vulnerability_count: number;
  ai_pipeline_degraded: boolean;
}

export interface PaginationMeta {
  page: number;
  per_page: number;
  total: number;
  total_pages: number;
  has_next: boolean;
  has_prev: boolean;
}

export interface PaginatedScansResponse {
  items: ScanListItem[];
  pagination: PaginationMeta;
}

export interface ProjectResponse {
  id: string;
  organization_id: string;
  name: string;
  target_url: string;
  root_domain: string;
  source_repo_url: string | null;
  container_image: string | null;
  domain_verified: boolean;
  verification_token: string;
  archived_at: string | null;
  created_at: string;
}

export interface PaginatedProjectsResponse {
  items: ProjectResponse[];
  pagination: PaginationMeta;
}

export interface ScanJobDetail {
  id: string;
  engine: string;
  target_url: string;
  status: "queued" | "running" | "completed" | "failed" | "canceled" | string;
  finding_count: number;
  duration_ms: number | null;
  error_message: string | null;
  created_at: string;
  updated_at: string;
}

export interface ScanDetailResponse {
  id: string;
  project_id: string;
  project_name: string;
  target_url: string;
  organization_id: string;
  scan_type: string;
  status: ScanStatus;
  priority: string;
  recon_enabled: boolean;
  subdomain_limit: number;
  mobile_upload_id: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  ai_pipeline_degraded: boolean;
  executive_summary_available: boolean;
  jobs: ScanJobDetail[];
  raw_finding_count: number;
  vulnerability_count: number;
  severity_counts: Record<Severity, number>;
}

export interface ScanCreateInput {
  scan_type: "quick" | "full_web" | "full_web_source" | "api" | "container";
  priority?: "low" | "normal" | "high";
  recon_enabled?: boolean;
  subdomain_limit?: number;
}

export interface ScanResponse {
  id: string;
  project_id: string;
  scan_type: string;
  status: ScanStatus;
}

export interface ProjectCreateInput {
  name: string;
  target_url: string;
  source_repo_url?: string | null;
  container_image?: string | null;
}

export interface VerifyDomainSuccess {
  verified: true;
  method: "dns_txt" | "meta_tag";
  project: ProjectResponse;
}

export interface VerifyDomainFailure {
  detail: "verification_failed";
  method: "dns_txt" | "meta_tag";
  failure_reason: string;
  expected_record: string;
}

/** One line of the per-scan progress stream (Redis stream → SSE). */
export interface ProgressEvent {
  id: string;
  event_type: string;
  timestamp?: string;
  engine?: string;
  job_id?: string;
  target?: string;
  domain?: string;
  count?: number;
  live_count?: number;
  subdomain_count?: number;
  finding_count?: number;
  duration_ms?: number;
  error?: string;
  status?: string;
  [k: string]: unknown;
}

export type VulnerabilityStatus = "open" | "resolved" | "false_positive" | "accepted_risk";
export type EngineCategory =
  "dast" | "sast" | "sca" | "mobile" | "infrastructure" | "recon" | "ssl";

export interface VulnerabilityListItem {
  id: string;
  title: string;
  severity: Severity;
  severity_score: number | null;
  status: VulnerabilityStatus;
  cwe_id: string | null;
  engine_category: EngineCategory;
  corroborated_count: number;
  scan_id: string;
  created_at: string;
  first_seen_at: string | null;
  previous_id: string | null;
  superseded_by_id: string | null;
  regression: boolean;
}

export interface VulnerabilityDetail extends VulnerabilityListItem {
  description: string | null;
  target_url: string | null;
  code_file: string | null;
  code_line: number | null;
  parameter: string | null;
  mobile_os: string | null;
  mobile_permission: string | null;
  mobile_component_name: string | null;
  correlation_cluster_id: string | null;
  updated_at: string;
}

export interface PaginatedVulnerabilitiesResponse {
  items: VulnerabilityListItem[];
  pagination: PaginationMeta;
}

export interface EvidenceItem {
  raw_finding_id: string;
  tool_name: string;
  engine_category: EngineCategory;
  description: string | null;
  code_snippet: string | null;
  code_file: string | null;
  code_line: number | null;
  target_url: string | null;
  parameter: string | null;
}

export interface FixResponse {
  vulnerability_id: string;
  ai_fix_text: string | null;
  is_fallback: boolean;
}

export interface VulnerabilityHistoryItem {
  id: string;
  from_status: VulnerabilityStatus;
  to_status: VulnerabilityStatus;
  changed_by: string | null;
  notes: string | null;
  created_at: string;
}

export interface MemberItem {
  user_id: string;
  email: string;
  full_name: string;
  role: "admin" | "member" | "viewer";
  email_verified: boolean;
  joined_at: string;
}

export interface MemberInviteResponse extends MemberItem {
  invited_new_user: boolean;
}

export interface OrgPatchInput {
  name?: string;
  industry?: string | null;
  country?: string | null;
  company_size?: string | null;
}

export interface APIKeySummary {
  id: string;
  name: string;
  key_prefix: string;
  last_used_at: string | null;
  revoked_at: string | null;
  created_at: string;
}

export interface APIKeyCreatedResponse {
  id: string;
  name: string;
  key_prefix: string;
  plaintext_key: string;
  created_at: string;
}

export interface ReportManifest {
  scan_id: string;
  status: ScanStatus;
  available_formats: string[];
  pdf: { generated: boolean; generated_at: string; size_bytes: number } | null;
}

export interface PdfReportResponse {
  format: "pdf";
  download_url: string;
  expires_at: string;
  expires_in: number;
  generated_at: string;
  size_bytes: number;
}

export interface ExecutiveReportResponse {
  scan_id: string;
  executive_summary: string | null;
  generated_at: string;
}

export interface PublicScanCreateResponse {
  slug: string;
  status: string;
  target_url: string;
  result_url: string;
  estimated_seconds: number;
  expires_at: string;
}

export interface PublicFinding {
  title: string;
  severity: Severity;
  engine: string;
  summary: string | null;
  target_url: string | null;
}

export interface PublicScanResult {
  slug: string;
  status: ScanStatus | "expired";
  target_url: string;
  domain: string;
  created_at: string;
  completed_at: string | null;
  expires_at: string;
  engines_total: number;
  engines_finished: number;
  score: number | null;
  grade: string | null;
  findings_by_severity: Record<Severity, number> & { total: number };
  findings: PublicFinding[];
  hidden_count: number;
  register_url: string;
}

export type ControlState = "pass" | "fail" | "not_assessed";

export interface PostureSummary {
  pass: number;
  fail: number;
  not_assessed: number;
  total: number;
}

export interface FrameworkPosture {
  slug: string;
  name: string;
  version: string;
  controls: Array<{ control_id: string; title: string; state: ControlState }>;
  summary: PostureSummary;
}

export interface OrgPostureResponse {
  organization_id: string;
  frameworks: FrameworkPosture[];
}

export interface FrameworkCatalog {
  frameworks: Array<{
    slug: string;
    name: string;
    version: string;
    controls: Array<{ control_id: string; title: string; description: string | null }>;
  }>;
}

export interface ToolHealthResponse {
  workers: Array<{
    worker_id: string | null;
    hostname: string | null;
    concurrency: number | null;
    last_seen: string | null;
    engines: string[];
  }>;
  tools: Array<{ engine: string; available: boolean; live_worker_count: number }>;
  checked_at: string;
}

// ---------------------------------------------------------------- plans & billing (M12)

export interface PlanPrice {
  version_id: string;
  billing_interval: "month" | "year";
  price_egp_cents: number;
  price_usd_cents: number;
  limits: Record<string, number>;
  features: Record<string, boolean | string[]>;
}

export interface PlanPublic {
  code: string;
  name: string;
  description: string | null;
  rank: number | null;
  prices: PlanPrice[];
}

export interface PlanCatalogResponse {
  plans: PlanPublic[];
  vat_included: boolean;
  vat_rate_percent: number;
}

export interface BillingSummaryResponse {
  plan_code: string;
  plan_name: string;
  billing_interval: "month" | "year";
  subscription_status: string;
  period_start: string;
  period_end: string | null;
  limits: Record<string, number>;
  features: Record<string, boolean | string[]>;
  usage: Record<string, number>;
  overrides: string[];
}

// ---------------------------------------------------------------- platform admin (M12 slice 3)

export interface AdminPlanVersion {
  id: string;
  plan_id: string;
  version: number;
  billing_interval: "month" | "year";
  price_egp_cents: number;
  price_usd_cents: number;
  limits: Record<string, number>;
  features: Record<string, boolean | string[]>;
  paymob_plan_id: string | null;
  paddle_price_id: string | null;
  effective_from: string;
  retired_at: string | null;
  change_note: string | null;
  created_by: string | null;
  created_at: string;
}

export interface AdminPlan {
  id: string;
  code: string;
  name: string;
  description: string | null;
  rank: number | null;
  is_public: boolean;
  archived_at: string | null;
  live_versions: AdminPlanVersion[];
  version_count: number;
  subscriber_count: number;
}

export interface AdminPlanList {
  plans: AdminPlan[];
  limit_keys: string[];
  feature_keys: string[];
}

export interface AdminVersionInput {
  billing_interval: "month" | "year";
  price_egp_cents: number;
  price_usd_cents: number;
  limits: Record<string, number>;
  features: Record<string, boolean | string[]>;
  change_note?: string;
}

export interface AdminVersionPublished {
  version: AdminPlanVersion;
  retired: AdminPlanVersion | null;
  diff: { field: string; before: unknown; after: unknown }[];
}

export interface AdminOrgSummary {
  id: string;
  name: string;
  slug: string;
  created_at: string;
  members: number;
  plan_code: string;
  subscription_status: string;
  provider: string | null;
}

export interface AdminOrgList {
  orgs: AdminOrgSummary[];
  total: number;
}

export interface AdminOverride {
  key: string;
  value: unknown;
  reason: string | null;
  expires_at: string | null;
  set_by: string | null;
  updated_at: string;
}

export interface AdminOrgDetail {
  org: AdminOrgSummary;
  subscription: {
    id: string;
    plan_version_id: string;
    status: string;
    provider: string;
    current_period_start: string;
    current_period_end: string | null;
    note: string | null;
  } | null;
  overrides: AdminOverride[];
  effective_limits: Record<string, number>;
  effective_features: Record<string, boolean | string[]>;
  usage: Record<string, number>;
  period_start: string;
  period_end: string | null;
}

// ---------------------------------------------------------------- billing (M12 slice 4)

export interface InvoiceView {
  id: string;
  status: "paid" | "failed" | "refunded";
  amount_cents: number;
  currency: string;
  vat_cents: number;
  period_start: string | null;
  period_end: string | null;
  paid_at: string | null;
  failure_reason: string | null;
  created_at: string;
}

export interface SubscriptionView {
  plan_code: string;
  plan_name: string;
  billing_interval: "month" | "year";
  status: string;
  provider: string;
  current_period_start: string;
  current_period_end: string | null;
  cancel_at_period_end: boolean;
  past_due_since: string | null;
  online_checkout: boolean;
  pending_checkout: boolean;
  invoices: InvoiceView[];
}

// ---------------------------------------------------------------- scan comparison (identity links)

export interface ComparedFinding {
  id: string;
  scan_id: string;
  title: string;
  severity: Severity;
  status: VulnerabilityStatus;
  finding_type: string;
  cwe_id: string | null;
  target_url: string | null;
  first_seen_at: string | null;
  resolved_at: string | null;
  regression: boolean;
}

export interface ComparedScan {
  id: string;
  scan_type: string;
  status: ScanStatus;
  created_at: string;
  completed_at: string | null;
}

export interface ScanComparison {
  baseline: ComparedScan;
  current: ComparedScan;
  summary: {
    new: number;
    regressions: number;
    persisting: number;
    fixed: number;
    not_covered: number;
    triaged: number;
    truncated: boolean;
    scope_covered: boolean;
    scope_known: boolean;
  };
  new: ComparedFinding[];
  regressions: ComparedFinding[];
  persisting: ComparedFinding[];
  fixed: ComparedFinding[];
  not_covered: ComparedFinding[];
}
