/**
 * /register — creates user + organization, then shows "check your email".
 * `?from=<quick-scan slug>` (flow F1) pre-fills the org name from the
 * scanned domain once the public result is loaded; the email itself is
 * never exposed by the public endpoint, so the user types it.
 */

import { useState } from "react";
import type { FormEvent } from "react";
import { Link, useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useRegister } from "@/lib/queries";
import { Alert, Button, Field, Input } from "@/components/ui";
import { AuthLayout } from "./AuthLayout";
import { authErrorMessage } from "@/lib/errors";

interface QuickScanPeek {
  domain: string;
  grade: string | null;
  findings_by_severity: { total: number };
}

function titleCase(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : "";
}

export default function Register() {
  const [params] = useSearchParams();
  const from = params.get("from");
  const register = useRegister();
  const [form, setForm] = useState({
    full_name: "",
    email: "",
    organization_name: "",
    password: "",
  });
  const [orgTouched, setOrgTouched] = useState(false);
  const [done, setDone] = useState(false);

  const peek = useQuery({
    queryKey: ["public", "quick-scan", from],
    queryFn: () => api<QuickScanPeek>(`/v1/public/quick-scans/${from}`, { anonymous: true }),
    enabled: from !== null,
    retry: false,
  });

  // Suggested org name from the quick-scan domain, until the user edits it.
  const suggestedOrg = peek.data
    ? titleCase(peek.data.domain.replace(/^www\./, "").split(".")[0] ?? "")
    : "";
  const organizationName = orgTouched
    ? form.organization_name
    : form.organization_name || suggestedOrg;

  function set<K extends keyof typeof form>(k: K) {
    return (e: { target: { value: string } }) => {
      if (k === "organization_name") setOrgTouched(true);
      setForm((f) => ({ ...f, [k]: e.target.value }));
    };
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    await register.mutateAsync({
      ...form,
      organization_name: organizationName,
      email: form.email.trim(),
    });
    setDone(true);
  }

  if (done) {
    return (
      <AuthLayout
        title="Check your email"
        lede={`We sent a verification link to ${form.email.trim()}.`}
      >
        <p className="text-sm text-ink-3">
          Scans and API keys need a verified address. The link is valid for 24 hours. Once verified,{" "}
          <Link
            to={`/login?email=${encodeURIComponent(form.email.trim())}`}
            className="font-medium text-brand"
          >
            sign in
          </Link>
          .
        </p>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout
      title="Create your account"
      lede="Free tier: one full scan a month, all 14 engines, no card."
      footer={
        <>
          Already have an account?{" "}
          <Link to="/login" className="font-medium text-brand">
            Sign in
          </Link>
        </>
      }
    >
      {peek.data && (
        <div className="mb-4">
          <Alert tone="info">
            Your quick scan of <strong>{peek.data.domain}</strong>
            {peek.data.grade ? ` graded ${peek.data.grade}` : ""} with{" "}
            {peek.data.findings_by_severity.total} findings. Create an account to see all of them
            and run a full scan.
          </Alert>
        </div>
      )}
      <form onSubmit={onSubmit} className="flex flex-col gap-4" noValidate>
        {register.isError && <Alert tone="error">{authErrorMessage(register.error)}</Alert>}
        <Field label="Your name">
          {(id) => (
            <Input
              id={id}
              autoComplete="name"
              required
              value={form.full_name}
              onChange={set("full_name")}
            />
          )}
        </Field>
        <Field label="Work email">
          {(id) => (
            <Input
              id={id}
              type="email"
              autoComplete="email"
              required
              value={form.email}
              onChange={set("email")}
            />
          )}
        </Field>
        <Field label="Organization">
          {(id) => (
            <Input
              id={id}
              autoComplete="organization"
              required
              value={organizationName}
              onChange={set("organization_name")}
            />
          )}
        </Field>
        <Field label="Password" hint="At least 8 characters.">
          {(id, by) => (
            <Input
              id={id}
              type="password"
              autoComplete="new-password"
              required
              minLength={8}
              value={form.password}
              onChange={set("password")}
              aria-describedby={by}
            />
          )}
        </Field>
        <Button type="submit" loading={register.isPending} className="mt-2">
          Create account
        </Button>
      </form>
    </AuthLayout>
  );
}
