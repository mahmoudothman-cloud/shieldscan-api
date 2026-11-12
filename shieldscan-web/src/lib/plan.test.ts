import { describe, expect, it } from "vitest";

import { ApiError } from "@/lib/api";
import { planLimitMessage, planLimitOf } from "@/lib/plan";

const detail = {
  error: "plan_limit_reached" as const,
  key: "scans.full.per_period",
  limit: 1,
  current: 1,
  plan: "free",
  upgrade_url: "https://app.example.com/settings/billing",
};

describe("planLimitOf", () => {
  it("decodes the API's 402 shape", () => {
    const d = planLimitOf(new ApiError(402, detail));
    expect(d?.key).toBe("scans.full.per_period");
    expect(planLimitMessage(d!)).toBe(
      "You've used 1 of 1 full scans this billing period on the Free plan.",
    );
  });
  it("ignores other errors", () => {
    expect(planLimitOf(new ApiError(402, "other"))).toBeNull();
    expect(planLimitOf(new ApiError(403, detail))).toBeNull();
    expect(planLimitOf(new Error("x"))).toBeNull();
  });
  it("words feature and cap limits", () => {
    expect(planLimitMessage({ ...detail, key: "cli_write", limit: false, current: false })).toMatch(
      /read-only/,
    );
    expect(planLimitMessage({ ...detail, key: "projects.max", limit: 1, current: 1 })).toBe(
      "The Free plan allows 1 projects; you have 1.",
    );
  });
});
