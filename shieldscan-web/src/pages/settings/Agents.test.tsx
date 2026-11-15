/** Settings → Agents: list with status + tools, one-time token, revoke confirm, plan cap. */

import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Agents, isBehind } from "./Agents";
import { ApiError } from "@/lib/api";

vi.mock("@/lib/auth", () => ({ useOrgId: () => "org-1" }));

const apiMock =
  vi.fn<(path: string, opts?: { method?: string; body?: unknown }) => Promise<unknown>>();
vi.mock("@/lib/api", async (orig) => {
  const mod = await orig<typeof import("@/lib/api")>();
  return { ...mod, api: (p: string, o?: { method?: string; body?: unknown }) => apiMock(p, o) };
});

const dc1 = {
  id: "ag-1",
  name: "dc1",
  description: "Cairo office",
  status: "active",
  key_prefix: "ss_agent_abcde",
  enrolled_at: "2026-11-01T00:00:00Z",
  last_seen_at: new Date().toISOString(),
  version: "v0.1.0",
  hostname: "scanner-01",
  platform: "linux/amd64",
  tools: { nuclei: { status: "ok", version: "3.4" }, nikto: { status: "missing" } },
  project_count: 2,
  created_at: "2026-11-01T00:00:00Z",
};
const stale = {
  ...dc1,
  id: "ag-2",
  name: "lab",
  status: "offline",
  version: "v0.0.9",
  tools: {},
  project_count: 0,
};

function setup({ isAdmin = true, capped = false } = {}) {
  apiMock.mockImplementation((path, opts) => {
    const m = opts?.method ?? "GET";
    if (path === "/v1/orgs/org-1/agents" && m === "GET")
      return Promise.resolve({ agents: [dc1, stale], latest_version: "v0.1.0" });
    if (path === "/v1/orgs/org-1/agents" && m === "POST") {
      if (capped)
        return Promise.reject(
          new ApiError(402, {
            error: "plan_limit_reached",
            key: "agents.max",
            limit: 1,
            current: 1,
            plan: "growth",
            upgrade_url: "/settings/billing",
          }),
        );
      return Promise.resolve({
        agent: {
          ...dc1,
          id: "ag-3",
          name: (opts?.body as { name: string }).name,
          status: "pending",
          tools: {},
        },
        enrolment_token: "ss_enrol_ONCE",
        enrolment_expires_at: "2026-11-16T00:00:00Z",
        enrol_command:
          "shieldscan-agent enroll --api https://app.example.com --token ss_enrol_ONCE",
      });
    }
    if (path === "/v1/orgs/org-1/agents/ag-1" && m === "DELETE") return Promise.resolve(null);
    return Promise.reject(new Error(`unexpected ${m} ${path}`));
  });
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <Agents isAdmin={isAdmin} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("<Agents />", () => {
  it("lists agents with status, version, tools and missing-tool warning", async () => {
    setup();
    expect(await screen.findByText("dc1")).toBeInTheDocument();
    expect(screen.getByText("online")).toBeInTheDocument();
    expect(screen.getByText("offline")).toBeInTheDocument();
    expect(screen.getByText("v0.1.0")).toBeInTheDocument();
    expect(screen.getAllByText(/scanner-01 \(linux\/amd64\)/)).toHaveLength(2);
    expect(screen.getByText(/Missing on the agent: nikto/)).toBeInTheDocument();
    // lab runs v0.0.9 behind the v0.1.0 release; dc1 is current.
    expect(screen.getAllByText(/update available · v0\.1\.0/)).toHaveLength(1);
  });

  it("admin creates an agent and sees the one-time enrol command", async () => {
    setup();
    await screen.findByText("dc1");
    await userEvent.type(screen.getByLabelText("New agent name"), "dc2");
    await userEvent.click(screen.getByRole("button", { name: "Create agent" }));
    expect(await screen.findByText(/shown once/)).toBeInTheDocument();
    expect(
      screen.getByText(
        "shieldscan-agent enroll --api https://app.example.com --token ss_enrol_ONCE",
      ),
    ).toBeInTheDocument();
    const post = apiMock.mock.calls.find((c) => c[1]?.method === "POST");
    expect(post?.[1]?.body).toEqual({ name: "dc2", description: null });
  });

  it("plan cap on create renders the plan-limit alert", async () => {
    setup({ capped: true });
    await screen.findByText("dc1");
    await userEvent.type(screen.getByLabelText("New agent name"), "dc2");
    await userEvent.click(screen.getByRole("button", { name: "Create agent" }));
    expect(
      await screen.findByText(/The Growth plan allows 1 on-prem agents; you have 1\./),
    ).toBeInTheDocument();
  });

  it("revoke asks first, then DELETEs", async () => {
    setup();
    await screen.findByText("dc1");
    await userEvent.click(screen.getAllByRole("button", { name: "Revoke" })[0]);
    expect(screen.getByText(/its projects are unbound/)).toBeInTheDocument();
    // The confirming row's danger button comes first in DOM order; lab's ghost button follows.
    await userEvent.click(screen.getAllByRole("button", { name: "Revoke" })[0]);
    const del = apiMock.mock.calls.find((c) => c[1]?.method === "DELETE");
    expect(del?.[0]).toBe("/v1/orgs/org-1/agents/ag-1");
  });

  it("member: no create form, no revoke buttons", async () => {
    setup({ isAdmin: false });
    await screen.findByText("dc1");
    expect(screen.queryByLabelText("New agent name")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Revoke" })).not.toBeInTheDocument();
  });
});

describe("isBehind", () => {
  it("compares semver, tolerating dev builds and unknowns", () => {
    expect(isBehind("v0.1.0", "v0.2.0")).toBe(true);
    expect(isBehind("v0.2.0", "v0.2.0")).toBe(false);
    expect(isBehind("0.0.9-dev+abc", "v0.1.0")).toBe(true);
    expect(isBehind("dev", "v0.1.0")).toBe(false);
    expect(isBehind("v0.1.0", null)).toBe(false);
  });
});
