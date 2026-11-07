/**
 * /reset-password?token=…  and  /accept-invite?reset=…&verify=…
 *
 * Both set a password from a reset token. The invite variant also
 * consumes the email-verification token first so the new teammate can
 * sign in immediately (reset alone does not verify the address).
 */

import { useState } from "react";
import type { FormEvent } from "react";
import { Link, useSearchParams } from "react-router";
import { useResetPassword, useVerifyEmail } from "@/lib/queries";
import { Alert, Button, Field, Input } from "@/components/ui";
import { AuthLayout } from "./AuthLayout";
import { authErrorMessage } from "@/lib/errors";

export default function ResetPassword({ invite = false }: { invite?: boolean }) {
  const [params] = useSearchParams();
  const resetToken = params.get(invite ? "reset" : "token");
  const verifyToken = params.get("verify");
  const reset = useResetPassword();
  const verify = useVerifyEmail();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [mismatch, setMismatch] = useState(false);

  if (!resetToken) {
    return (
      <AuthLayout title={invite ? "Invitation link incomplete" : "Reset link incomplete"}>
        <Alert tone="error">
          This link is missing its token. Open the link from your email again.
        </Alert>
      </AuthLayout>
    );
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (!resetToken) return;
    if (password !== confirm) {
      setMismatch(true);
      return;
    }
    setMismatch(false);
    if (invite && verifyToken && verify.isIdle) {
      try {
        await verify.mutateAsync(verifyToken);
      } catch {
        // A used/expired verify token must not block setting the password;
        // the user can resend verification afterwards.
      }
    }
    await reset.mutateAsync({ token: resetToken, new_password: password });
  }

  if (reset.isSuccess) {
    return (
      <AuthLayout title={invite ? "You're in" : "Password updated"}>
        <div className="flex flex-col gap-4">
          <Alert tone="success">
            {invite
              ? "Your account is ready."
              : "Your password has been changed and other sessions were signed out."}
          </Alert>
          <Link to="/login">
            <Button>Sign in</Button>
          </Link>
        </div>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout
      title={invite ? "Set your password" : "Choose a new password"}
      lede={invite ? "You've been invited to a ShieldScan organization." : undefined}
    >
      <form onSubmit={onSubmit} className="flex flex-col gap-4" noValidate>
        {reset.isError && <Alert tone="error">{authErrorMessage(reset.error)}</Alert>}
        <Field label="New password" hint="At least 8 characters.">
          {(id, by) => (
            <Input
              id={id}
              type="password"
              autoComplete="new-password"
              required
              minLength={8}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              aria-describedby={by}
            />
          )}
        </Field>
        <Field label="Confirm password" error={mismatch ? "Passwords don't match." : undefined}>
          {(id, by) => (
            <Input
              id={id}
              type="password"
              autoComplete="new-password"
              required
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              aria-describedby={by}
              aria-invalid={mismatch}
            />
          )}
        </Field>
        <Button type="submit" loading={reset.isPending || verify.isPending}>
          {invite ? "Activate account" : "Set password"}
        </Button>
      </form>
    </AuthLayout>
  );
}
