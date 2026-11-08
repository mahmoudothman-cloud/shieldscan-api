/** Report page: 409 before terminal, PDF request opens the signed URL, inline downloads. */

import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import ScanReport from "./ScanReport";
import { ApiError } from "@/lib/api";

vi.mock("@/lib/auth", () => ({ useOrgId: () => "org-1" }));
const apiMock = vi.fn<(path: string) => Promise<unknown>>();
vi.mock("@/lib/api", async (orig) => {
  const mod = await orig<typeof import("@/lib/api")>();
  return { ...mod, api: (p: string) => apiMock(p) };
});

const scan = (status: string) => ({
  id: "s1",
  project_id: "p1",
  project_name: "Shop",
  target_url: "https://shop.example.com",
  organization_id: "org-1",
  scan_type: "full_web",
  status,
  priority: "normal",
  recon_enabled: true,
  subdomain_limit: 100,
  mobile_upload_id: null,
  created_at: "2026-11-07T10:00:00Z",
  started_at: "2026-11-07T10:00:00Z",
  completed_at: status === "running" ? null : "2026-11-07T10:30:00Z",
  error_message: null,
  ai_pipeline_degraded: false,
  executive_summary_available: true,
  jobs: [],
  raw_finding_count: 394,
  vulnerability_count: 40,
  severity_counts: { critical: 0, high: 0, medium: 4, low: 10, info: 26 },
});

function setup(status: string) {
  apiMock.mockImplementation((path) => {
    if (path === "/v1/orgs/org-1/scans/s1") return Promise.resolve(scan(status));
    if (path === "/v1/orgs/org-1/scans/s1/report")
      return status === "running"
        ? Promise.reject(new ApiError(409, "scan not yet complete"))
        : Promise.resolve({
            scan_id: "s1",
            status,
            available_formats: ["pdf", "sarif", "json", "executive"],
            pdf: null,
          });
    if (path.endsWith("/report/executive"))
      return Promise.resolve({
        scan_id: "s1",
        executive_summary: "## Executive Summary\n\nNo critical issues.",
        generated_at: "",
      });
    if (path.endsWith("/report/pdf"))
      return Promise.resolve({
        format: "pdf",
        download_url: "https://r2.example/x.pdf?sig=1",
        expires_at: "",
        expires_in: 3600,
        generated_at: "",
        size_bytes: 204800,
      });
    return Promise.reject(new Error(path));
  });
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/scans/s1/report"]}>
        <Routes>
          <Route path="/scans/:scanId/report" element={<ScanReport />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("<ScanReport />", () => {
  it("explains that a running scan has no report yet", async () => {
    setup("running");
    expect(await screen.findByText(/available once the scan finishes/)).toBeInTheDocument();
  });

  it("renders the executive summary and opens the signed PDF URL", async () => {
    const open = vi.fn();
    vi.stubGlobal("open", open);
    setup("completed");
    expect(await screen.findByText("No critical issues.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Generate PDF/ }));
    expect(await screen.findByText(/PDF ready \(200 KB\)/)).toBeInTheDocument();
    expect(open).toHaveBeenCalledWith("https://r2.example/x.pdf?sig=1", "_blank", "noopener");
    vi.unstubAllGlobals();
  });
});
