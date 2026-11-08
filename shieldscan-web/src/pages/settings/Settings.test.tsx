/** Settings: admin controls, invite payload, last-admin guard message, one-time key display. */

import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import Settings from "./Settings";
import { ApiError } from "@/lib/api";

const me = {
  kind: "jwt",
  user: { id: "u-admin", email: "admin@acme.com", full_name: "Ada Admin", email_verified: true },
  organization: { id: "org-1", name: "Acme", slug: "acme" },
};
vi.mock("@/lib/auth", () => ({
  useOrgId: () => "org-1",
  useAuth: () => ({
    status: "authenticated",
    me,
    orgId: "org-1",
    signIn: vi.fn(),
    signOut: vi.fn(),
  }),
}));

type Call = { path: string; method: string | undefined; body: unknown };
const apiMock =
  vi.fn<(path: string, opts?: { method?: string; body?: unknown }) => Promise<unknown>>();
vi.mock("@/lib/api", async (orig) => {
  const mod = await orig<typeof import("@/lib/api")>();
  return { ...mod, api: (p: string, o?: { method?: string; body?: unknown }) => apiMock(p, o) };
});

const org = (role: string) => ({
  id: "org-1",
  name: "Acme",
  slug: "acme",
  industry: null,
  country: "EG",
  company_size: null,
  created_at: "2026-11-01T00:00:00Z",
  member_count: 2,
  my_role: role,
});
const members = [
  {
    user_id: "u-admin",
    email: "admin@acme.com",
    full_name: "Ada Admin",
    role: "admin",
    email_verified: true,
    joined_at: "2026-11-01T00:00:00Z",
  },
  {
    user_id: "u-mem",
    email: "mo@acme.com",
    full_name: "Mo Member",
    role: "member",
    email_verified: false,
    joined_at: "2026-11-05T00:00:00Z",
  },
];

function setup(role = "admin") {
  apiMock.mockImplementation((path, opts) => {
    const m = opts?.method ?? "GET";
    if (path === "/v1/orgs/org-1" && m === "GET") return Promise.resolve(org(role));
    if (path === "/v1/orgs/org-1/members" && m === "GET") return Promise.resolve(members);
    if (path === "/v1/orgs/org-1/members" && m === "POST")
      return Promise.resolve({
        ...members[1],
        email: "new@acme.com",
        full_name: "new",
        invited_new_user: true,
      });
    if (path === "/v1/orgs/org-1/members/u-admin" && m === "PATCH")
      return Promise.reject(new ApiError(409, "last_admin"));
    if (path === "/v1/auth/api-keys" && m === "GET")
      return Promise.resolve([
        {
          id: "k1",
          name: "CI",
          key_prefix: "ss_live_abcd",
          last_used_at: null,
          revoked_at: null,
          created_at: "2026-11-01T00:00:00Z",
        },
      ]);
    if (path === "/v1/auth/api-keys" && m === "POST")
      return Promise.resolve({
        id: "k2",
        name: "x",
        key_prefix: "ss_live_zzzz",
        plaintext_key: "ss_live_zzzz_SECRET",
        created_at: "",
      });
    return Promise.reject(new Error(`unexpected ${m} ${path}`));
  });
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <Settings />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const calls = (): Call[] =>
  apiMock.mock.calls.map(([path, o]) => ({ path, method: o?.method, body: o?.body }));

describe("<Settings />", () => {
  it("admin: invites with email + role, shows the one-time API key", async () => {
    setup();
    await screen.findByText("Mo Member");
    await userEvent.type(screen.getByLabelText("Invite by work email"), "new@acme.com");
    await userEvent.selectOptions(screen.getByLabelText("Role"), "viewer");
    await userEvent.click(screen.getByRole("button", { name: "Send invite" }));
    expect(await screen.findByText(/Invitation sent to new@acme.com/)).toBeInTheDocument();
    const post = calls().find((c) => c.method === "POST" && c.path.endsWith("/members"));
    expect(post?.body).toEqual({ email: "new@acme.com", role: "viewer" });

    await userEvent.type(screen.getByLabelText("New key name"), "Deploy");
    await userEvent.click(screen.getByRole("button", { name: "Create key" }));
    expect(await screen.findByText("ss_live_zzzz_SECRET")).toBeInTheDocument();
  });

  it("admin: demoting the only admin surfaces the last-admin message", async () => {
    setup();
    await screen.findByText("Mo Member");
    await userEvent.selectOptions(screen.getByLabelText("Role for admin@acme.com"), "member");
    expect(
      await screen.findByText("An organization needs at least one admin."),
    ).toBeInTheDocument();
  });

  it("member: no invite form, roles read-only, org fields disabled", async () => {
    setup("member");
    await screen.findByText("Mo Member");
    expect(screen.queryByLabelText("Invite by work email")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Role for admin@acme.com")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Name")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Save changes" })).toBeDisabled();
  });
});
