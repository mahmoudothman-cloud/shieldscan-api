/** Public result: running → polls; completed → grade, top findings, hidden count, register CTA with slug; expired. */

import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import QuickScanResult from "./QuickScanResult";

vi.mock("@/lib/auth", () => ({
  useAuth: () => ({
    status: "anonymous",
    me: null,
    orgId: null,
    signIn: vi.fn(),
    signOut: vi.fn(),
  }),
}));
const apiMock = vi.fn<(path: string) => Promise<unknown>>();
vi.mock("@/lib/api", async (orig) => {
  const mod = await orig<typeof import("@/lib/api")>();
  return { ...mod, api: (p: string) => apiMock(p) };
});

const base = {
  slug: "abc",
  target_url: "https://shop.example.com",
  domain: "shop.example.com",
  created_at: new Date().toISOString(),
  completed_at: new Date().toISOString(),
  expires_at: new Date(Date.now() + 6.6 * 86400e3).toISOString(),
  engines_total: 2,
  engines_finished: 2,
  score: 69,
  grade: "C",
  findings_by_severity: { critical: 0, high: 1, medium: 2, low: 1, info: 1, total: 5 },
  findings: [
    {
      title: "Exposed .git directory",
      severity: "high",
      engine: "nuclei",
      summary: "The repo is downloadable.",
      target_url: "https://shop.example.com/.git/",
    },
  ],
  hidden_count: 4,
  register_url: "https://app/register?from=abc",
};

function setup(over: Record<string, unknown> & { status: string }) {
  apiMock.mockResolvedValue({ ...base, ...over });
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/q/abc"]}>
        <Routes>
          <Route path="/q/:slug" element={<QuickScanResult />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("<QuickScanResult />", () => {
  it("shows progress while running", async () => {
    setup({
      status: "running",
      engines_finished: 1,
      grade: null,
      score: null,
      findings: [],
      hidden_count: 0,
    });
    expect(await screen.findByText(/1 of 2 checks finished/)).toBeInTheDocument();
    expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "50");
  });

  it("completed: grade, visible findings, hidden count, register link with the slug, expiry in days", async () => {
    setup({ status: "completed" });
    expect(await screen.findByText("C")).toBeInTheDocument();
    expect(screen.getByText("69/100")).toBeInTheDocument();
    expect(screen.getByText("Exposed .git directory")).toBeInTheDocument();
    expect(screen.getByText(/4 more findings on this site/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Create account — it's free/ })).toHaveAttribute(
      "href",
      "/register?from=abc",
    );
    expect(screen.getByText(/expires in 7 days/)).toBeInTheDocument();
    expect(screen.getByText(/What this grade does not cover/)).toBeInTheDocument();
  });

  it("expired: offers a new scan and an account", async () => {
    setup({ status: "expired", findings: [], hidden_count: 0, grade: null, score: null });
    expect(await screen.findByText("This result has expired")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "New quick scan" })).toHaveAttribute(
      "href",
      "/quick-scan",
    );
  });
});
