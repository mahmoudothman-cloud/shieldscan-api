/** Project page: unverified → verification panel + full scan blocked, quick allowed. */

import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import ProjectDetail from "./ProjectDetail";
import type { ProjectResponse } from "@/lib/types";

vi.mock("@/lib/auth", () => ({ useOrgId: () => "org-1" }));

const project: ProjectResponse = {
  id: "p1",
  organization_id: "org-1",
  name: "Shop",
  target_url: "https://shop.example.com",
  root_domain: "example.com",
  source_repo_url: null,
  container_image: null,
  domain_verified: false,
  verification_token: "tok-abc",
  archived_at: null,
  created_at: "2026-11-01T00:00:00Z",
};

const apiMock =
  vi.fn<(path: string, opts?: { method?: string; body?: unknown }) => Promise<unknown>>();
vi.mock("@/lib/api", async (orig) => {
  const mod = await orig<typeof import("@/lib/api")>();
  return { ...mod, api: (p: string, o?: { method?: string; body?: unknown }) => apiMock(p, o) };
});

function setup() {
  apiMock.mockImplementation((path, opts) => {
    if (path === "/v1/orgs/org-1/projects/p1" && !opts?.method) return Promise.resolve(project);
    if (path.endsWith("/scans") && !opts?.method)
      return Promise.resolve({
        items: [],
        pagination: {
          page: 1,
          per_page: 10,
          total: 0,
          total_pages: 0,
          has_next: false,
          has_prev: false,
        },
      });
    if (path.endsWith("/scans") && opts?.method === "POST")
      return Promise.resolve({
        id: "scan-9",
        project_id: "p1",
        scan_type: "quick",
        status: "queued",
      });
    return Promise.reject(new Error(`unexpected ${path}`));
  });
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/projects/p1"]}>
        <Routes>
          <Route path="/projects/:projectId" element={<ProjectDetail />} />
          <Route path="/scans/:scanId" element={<p>scan page</p>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("<ProjectDetail /> unverified", () => {
  it("shows the TXT record and blocks full scans but allows quick", async () => {
    setup();
    expect(await screen.findByText("_shieldscan-verify.example.com")).toBeInTheDocument();
    expect(screen.getByText("tok-abc")).toBeInTheDocument();

    const select = screen.getByLabelText("Scan type") as HTMLSelectElement;
    expect(select.value).toBe("quick");
    expect(screen.getByRole("button", { name: /start quick scan/i })).toBeEnabled();

    await userEvent.selectOptions(select, "full_web");
    expect(screen.getByText("Verify the domain first.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /start full web scan/i })).toBeDisabled();
  });

  it("starts a quick scan and navigates to the run page", async () => {
    setup();
    await screen.findByText("_shieldscan-verify.example.com");
    await userEvent.click(screen.getByRole("button", { name: /start quick scan/i }));
    expect(await screen.findByText("scan page")).toBeInTheDocument();
    const post = apiMock.mock.calls.find((c) => c[1]?.method === "POST");
    expect(post?.[0]).toBe("/v1/orgs/org-1/projects/p1/scans");
    expect(post?.[1]?.body).toEqual({ scan_type: "quick" });
  });
});
