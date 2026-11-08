import type { VulnerabilityStatus } from "./types";

export const STATUS_LABEL: Record<VulnerabilityStatus, string> = {
  open: "Open",
  resolved: "Resolved",
  false_positive: "False positive",
  accepted_risk: "Accepted risk",
};
