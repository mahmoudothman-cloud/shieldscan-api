/** /login — email + password; redirects to `next` (default /dashboard). */

import { useState } from "react";
import type { FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { useAuth } from "@/lib/auth";
import { Alert, Button, Field, Input } from "@/components/ui";
import { AuthLayout } from "./AuthLayout";
import { authErrorMessage } from "@/lib/errors";

export default function Login() {
  const { signIn } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [email, setEmail] = useState(params.get("email") ?? "");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const next = params.get("next") ?? "/dashboard";

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await signIn(email.trim(), password);
      void navigate(next, { replace: true });
    } catch (err) {
      setError(authErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthLayout
      title="Sign in"
      footer={
        <>
          New here?{" "}
          <Link to="/register" className="font-medium text-brand">
            Create an account
          </Link>
        </>
      }
    >
      <form onSubmit={onSubmit} className="flex flex-col gap-4" noValidate>
        {error && (
          <Alert tone="error">
            {error}{" "}
            <Link to={`/verify-email?email=${encodeURIComponent(email)}`} className="underline">
              Resend verification
            </Link>
          </Alert>
        )}
        <Field label="Work email">
          {(id, by) => (
            <Input
              id={id}
              type="email"
              autoComplete="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              aria-describedby={by}
            />
          )}
        </Field>
        <Field label="Password">
          {(id, by) => (
            <Input
              id={id}
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              aria-describedby={by}
            />
          )}
        </Field>
        <div className="flex items-center justify-between">
          <Link to="/forgot-password" className="text-sm text-brand">
            Forgot password?
          </Link>
          <Button type="submit" loading={busy}>
            Sign in
          </Button>
        </div>
      </form>
    </AuthLayout>
  );
}
