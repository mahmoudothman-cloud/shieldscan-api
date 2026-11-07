/** Login page: submits credentials, shows the generic error, navigates to `next`. */

import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import Login from "./Login";

const signIn = vi.fn<(email: string, password: string) => Promise<void>>();

vi.mock("@/lib/auth", () => ({
  useAuth: () => ({ status: "anonymous", me: null, orgId: null, signIn, signOut: vi.fn() }),
}));

function renderLogin(initial = "/login") {
  const qc = new QueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initial]}>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/dashboard" element={<p>dashboard page</p>} />
          <Route path="/projects/42" element={<p>project 42</p>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("<Login />", () => {
  it("signs in and lands on the dashboard", async () => {
    signIn.mockResolvedValueOnce(undefined);
    renderLogin();
    await userEvent.type(screen.getByLabelText("Work email"), "me@acme.com");
    await userEvent.type(screen.getByLabelText("Password"), "Secret-123");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(signIn).toHaveBeenCalledWith("me@acme.com", "Secret-123");
    expect(await screen.findByText("dashboard page")).toBeInTheDocument();
  });

  it("honours ?next= after sign in", async () => {
    signIn.mockResolvedValueOnce(undefined);
    renderLogin("/login?next=%2Fprojects%2F42");
    await userEvent.type(screen.getByLabelText("Work email"), "me@acme.com");
    await userEvent.type(screen.getByLabelText("Password"), "x");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("project 42")).toBeInTheDocument();
  });

  it("shows the generic message on 401 and offers to resend verification", async () => {
    signIn.mockRejectedValueOnce(
      Object.assign(new Error("unauthorized"), { status: 401, detail: "unauthorized" }),
    );
    renderLogin();
    await userEvent.type(screen.getByLabelText("Work email"), "me@acme.com");
    await userEvent.type(screen.getByLabelText("Password"), "wrong");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /incorrect, or the email is not verified/,
    );
    expect(screen.getByRole("link", { name: "Resend verification" })).toHaveAttribute(
      "href",
      "/verify-email?email=me%40acme.com",
    );
  });
});
