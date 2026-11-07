/** /forgot-password — always answers the same way (no account enumeration). */

import { useState } from "react";
import type { FormEvent } from "react";
import { Link } from "react-router";
import { useForgotPassword } from "@/lib/queries";
import { Alert, Button, Field, Input } from "@/components/ui";
import { AuthLayout } from "./AuthLayout";
import { authErrorMessage } from "@/lib/errors";

export default function ForgotPassword() {
  const forgot = useForgotPassword();
  const [email, setEmail] = useState("");

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    forgot.mutate(email.trim());
  }

  return (
    <AuthLayout
      title="Reset your password"
      lede="Enter your email and we'll send a link that is valid for one hour."
      footer={
        <Link to="/login" className="font-medium text-brand">
          Back to sign in
        </Link>
      }
    >
      <form onSubmit={onSubmit} className="flex flex-col gap-4" noValidate>
        {forgot.isSuccess && (
          <Alert tone="success">
            If an account exists for that address, the link is on its way.
          </Alert>
        )}
        {forgot.isError && <Alert tone="error">{authErrorMessage(forgot.error)}</Alert>}
        <Field label="Work email">
          {(id) => (
            <Input
              id={id}
              type="email"
              autoComplete="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          )}
        </Field>
        <Button type="submit" loading={forgot.isPending}>
          Send reset link
        </Button>
      </form>
    </AuthLayout>
  );
}
