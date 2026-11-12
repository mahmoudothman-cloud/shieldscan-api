/**
 * Plan limits (M12). The API answers every cap with one shape:
 * 402 { detail: { error: "plan_limit_reached", key, limit, current, plan, upgrade_url } }.
 * `planLimitOf` decodes it from any error; the components render it.
 */
import { ApiError } from "@/lib/api";

export interface PlanLimitDetail {
  error: "plan_limit_reached";
  key: string;
  limit: number | boolean | string[] | null;
  current: number | boolean | string | null;
  plan: string;
  upgrade_url: string;
}

export const UNLIMITED = -1;

export function planLimitOf(err: unknown): PlanLimitDetail | null {
  if (!(err instanceof ApiError) || err.status !== 402) return null;
  const d = err.detail;
  if (d && typeof d === "object" && (d as { error?: unknown }).error === "plan_limit_reached") {
    return d as PlanLimitDetail;
  }
  return null;
}

export const LIMIT_LABELS: Record<string, string> = {
  "users.max": "members",
  "projects.max": "projects",
  "api_keys.max": "API keys",
  "scans.quick.per_period": "quick scans",
  "scans.full.per_period": "full scans",
  "scans.mobile.per_period": "mobile scans",
  "scans.full_spectrum.per_period": "full-spectrum scans",
  "recon.subdomains.max": "recon subdomains",
};

export const FEATURE_LABELS: Record<string, string> = {
  ai_fix: "AI fix generation",
  cross_layer: "cross-layer correlation",
  "compliance.frameworks": "compliance frameworks",
  cli_write: "CLI / MCP write access",
  priority_queue: "priority scan queue",
  sso: "single sign-on",
};

export function planName(code: string): string {
  return code ? code.charAt(0).toUpperCase() + code.slice(1) : code;
}

export function planLimitMessage(d: PlanLimitDetail): string {
  const plan = planName(d.plan);
  if (d.key === "cli_write")
    return `The ${plan} plan gives the CLI and MCP read-only access. Starting scans from the terminal needs Starter or above.`;
  if (d.key === "compliance.frameworks")
    return d.current
      ? `The ${String(d.current).toUpperCase()} framework is not part of the ${plan} plan.`
      : `Compliance mapping is not part of the ${plan} plan.`;
  if (d.key in FEATURE_LABELS)
    return `${capitalize(FEATURE_LABELS[d.key] ?? d.key)} is not part of the ${plan} plan.`;
  const what = LIMIT_LABELS[d.key] ?? d.key;
  if (d.key.endsWith(".per_period"))
    return `You've used ${String(d.current)} of ${String(d.limit)} ${what} this billing period on the ${plan} plan.`;
  return `The ${plan} plan allows ${String(d.limit)} ${what}; you have ${String(d.current)}.`;
}

export function formatLimit(n: number): string {
  return n === UNLIMITED ? "Unlimited" : String(n);
}

export function formatEgp(cents: number): string {
  return `${(cents / 100).toLocaleString("en-EG", { maximumFractionDigits: 0 })} EGP`;
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
