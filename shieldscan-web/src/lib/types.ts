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
  user: { id: string; email: string; full_name: string; email_verified: boolean } | null;
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
