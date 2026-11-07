/** /verify-email?token=… — consumes the token; without one, offers resend. */

import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { Link, useSearchParams } from "react-router";
import { useResendVerification, useVerifyEmail } from "@/lib/queries";
import { Alert, Button, Field, Input } from "@/components/ui";
import { AuthLayout } from "./AuthLayout";
import { authErrorMessage } from "@/lib/errors";

export default function VerifyEmail() {
  const [params] = useSearchParams();
  const token = params.get("token");
  const verify = useVerifyEmail();
  const resend = useResendVerification();
  const [email, setEmail] = useState(params.get("email") ?? "");

  useEffect(() => {
    if (token && verify.isIdle) verify.mutate(token);
  }, [token, verify]);

  if (token) {
    return (
      <AuthLayout title="Verifying your email">
        {verify.isPending && <p className="text-sm text-ink-3">One moment…</p>}
        {verify.isSuccess && (
          <div className="flex flex-col gap-4">
            <Alert tone="success">Your email is verified.</Alert>
            <Link to="/login">
              <Button>Sign in</Button>
            </Link>
          </div>
        )}
        {verify.isError && (
          <div className="flex flex-col gap-4">
            <Alert tone="error">{authErrorMessage(verify.error)}</Alert>
            <Link to="/verify-email" className="text-sm text-brand">
              Request a new link
            </Link>
          </div>
        )}
      </AuthLayout>
    );
  }

  function onResend(e: FormEvent) {
    e.preventDefault();
    resend.mutate(email.trim());
  }

  return (
    <AuthLayout
      title="Resend verification"
      lede="We'll send a fresh link if an unverified account exists for this address."
    >
      <form onSubmit={onResend} className="flex flex-col gap-4" noValidate>
        {resend.isSuccess && (
          <Alert tone="success">If that address needs verifying, a new link is on its way.</Alert>
        )}
        {resend.isError && <Alert tone="error">{authErrorMessage(resend.error)}</Alert>}
        <Field label="Work email">
          {(id) => (
            <Input
              id={id}
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          )}
        </Field>
        <Button type="submit" loading={resend.isPending}>
          Send link
        </Button>
      </form>
    </AuthLayout>
  );
}
