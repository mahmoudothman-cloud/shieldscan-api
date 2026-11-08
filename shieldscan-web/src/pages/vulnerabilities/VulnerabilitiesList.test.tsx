/** Explorer: filters round-trip through the URL and reach the API as query params. */

import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import VulnerabilitiesList from "./VulnerabilitiesList";

vi.mock("@/lib/auth", () => ({ useOrgId: () => "org-1" }));
const apiMock = vi.fn<(path: string) => Promise<unknown>>();
vi.mock("@/lib/api", async (orig) => {
  const mod = await orig<typeof import("@/lib/api")>();
  return { ...mod, api: (p: string) => apiMock(p) };
});

const empty = {
  items: [],
  pagination: { page: 1, per_page: 25, total: 0, total_pages: 0, has_next: false, has_prev: false },
};

function setup(initial = "/vulnerabilities") {
  apiMock.mockImplementation((path) => {
    if (path.includes("/projects"))
      return Promise.resolve({ items: [{ id: "p1", name: "Shop" }], pagination: empty.pagination });
    if (path.includes("/vulnerabilities"))
      return Promise.resolve({
        items: [
          {
            id: "v1",
            title: "SQL injection in /login",
            severity: "critical",
            severity_score: 9.4,
            status: "open",
            cwe_id: "CWE-89",
            engine_category: "dast",
            corroborated_count: 2,
            scan_id: "s1",
            created_at: "2026-11-07T10:00:00Z",
          },
        ],
        pagination: {
          page: 1,
          per_page: 25,
          total: 1,
          total_pages: 1,
          has_next: false,
          has_prev: false,
        },
      });
    return Promise.reject(new Error(path));
  });
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initial]}>
        <Routes>
          <Route path="/vulnerabilities" element={<VulnerabilitiesList />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function lastVulnCall(): string {
  return (
    [...apiMock.mock.calls].reverse().find((c) => c[0].includes("/vulnerabilities"))?.[0] ?? ""
  );
}

describe("<VulnerabilitiesList />", () => {
  it("defaults to open issues sorted by score, and shows corroboration", async () => {
    setup();
    expect(await screen.findByText("SQL injection in /login")).toBeInTheDocument();
    const url = new URL(lastVulnCall(), "http://x");
    expect(url.searchParams.get("status")).toBe("open");
    expect(url.searchParams.get("sort")).toBe("-severity_score");
    expect(url.searchParams.get("severity")).toBeNull();
    expect(screen.getByText("confirmed by 2 engines")).toBeInTheDocument();
  });

  it("severity chips toggle into a CSV filter; scan_id deep link is forwarded", async () => {
    setup("/vulnerabilities?scan_id=s1");
    await screen.findByText("SQL injection in /login");
    expect(new URL(lastVulnCall(), "http://x").searchParams.get("scan_id")).toBe("s1");
    await userEvent.click(screen.getByRole("button", { name: "critical" }));
    await userEvent.click(screen.getByRole("button", { name: "high" }));
    await waitFor(() =>
      expect(new URL(lastVulnCall(), "http://x").searchParams.get("severity")).toBe(
        "critical,high",
      ),
    );
    await userEvent.click(screen.getByRole("button", { name: "critical" }));
    await waitFor(() =>
      expect(new URL(lastVulnCall(), "http://x").searchParams.get("severity")).toBe("high"),
    );
    expect(screen.getByRole("link", { name: /back to the scan/ })).toHaveAttribute(
      "href",
      "/scans/s1",
    );
  });

  it("'Any status' sends an empty status so resolved issues appear", async () => {
    setup();
    await screen.findByText("SQL injection in /login");
    await userEvent.selectOptions(screen.getByLabelText("Status"), "");
    await waitFor(() =>
      expect(new URL(lastVulnCall(), "http://x").searchParams.has("status")).toBe(false),
    );
  });
});
