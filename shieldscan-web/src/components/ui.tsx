/**
 * Small, typed UI primitives shared across pages. Deliberately plain —
 * no component library — so the design tokens in index.css are the
 * single source of look and feel.
 */

import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
} from "react";
import { useId } from "react";
import { Loader2 } from "lucide-react";
import type { Severity } from "@/lib/types";

import { cx } from "@/lib/cx";

// ---------------------------------------------------------------- Button

type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  loading?: boolean;
  size?: "sm" | "md";
}

const variantClass: Record<ButtonVariant, string> = {
  primary: "bg-brand text-white hover:bg-[#0b6b74] disabled:bg-brand/50",
  secondary: "bg-paper text-ink border border-line hover:bg-wash-2 disabled:text-muted",
  ghost: "text-ink-3 hover:bg-wash-2 hover:text-ink",
  danger: "bg-critical text-white hover:bg-[#b42318]",
};

export function Button({
  variant = "primary",
  size = "md",
  loading = false,
  className,
  children,
  disabled,
  ...rest
}: ButtonProps) {
  return (
    <button
      {...rest}
      disabled={disabled || loading}
      className={cx(
        "inline-flex items-center justify-center gap-2 rounded-control font-medium transition-colors",
        "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand",
        size === "sm" ? "h-8 px-3 text-sm" : "h-10 px-4 text-sm",
        variantClass[variant],
        className,
      )}
    >
      {loading && <Loader2 className="size-4 animate-spin" aria-hidden />}
      {children}
    </button>
  );
}

// ---------------------------------------------------------------- Field / Input

interface FieldProps {
  label: string;
  hint?: string;
  error?: string | undefined;
  children: (id: string, describedBy: string | undefined) => ReactNode;
}

export function Field({ label, hint, error, children }: FieldProps) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errId = `${id}-err`;
  const describedBy = error ? errId : hint ? hintId : undefined;
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-sm font-medium text-ink">
        {label}
      </label>
      {children(id, describedBy)}
      {error ? (
        <p id={errId} role="alert" className="text-sm text-critical">
          {error}
        </p>
      ) : hint ? (
        <p id={hintId} className="text-sm text-muted">
          {hint}
        </p>
      ) : null}
    </div>
  );
}

export function Input({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...rest}
      className={cx(
        "h-10 w-full rounded-control border border-line bg-paper px-3 text-sm text-ink",
        "placeholder:text-muted focus:border-brand focus:outline-2 focus:outline-brand/30",
        "aria-[invalid=true]:border-critical",
        className,
      )}
    />
  );
}

export function Select({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      {...rest}
      className={cx(
        "h-10 w-full rounded-control border border-line bg-paper px-3 text-sm text-ink",
        "focus:border-brand focus:outline-2 focus:outline-brand/30",
        className,
      )}
    >
      {children}
    </select>
  );
}

// ---------------------------------------------------------------- Card

export function Card({
  title,
  action,
  children,
  className,
}: {
  title?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={cx("rounded-card border border-line bg-paper", className)}>
      {(title || action) && (
        <header className="flex items-center justify-between border-b border-line-2 px-5 py-3">
          {title && <h2 className="text-sm font-semibold text-ink">{title}</h2>}
          {action}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  );
}

// ---------------------------------------------------------------- Badges

const severityStyle: Record<Severity, string> = {
  critical: "bg-critical-wash text-critical",
  high: "bg-high-wash text-high",
  medium: "bg-medium-wash text-medium",
  low: "bg-low-wash text-low",
  info: "bg-low-wash text-muted",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={cx(
        "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium capitalize",
        severityStyle[severity],
      )}
    >
      {severity}
    </span>
  );
}

export function StatusBadge({ status, detail }: { status: string; detail?: string }) {
  const tone =
    status === "completed"
      ? "bg-ok-wash text-ok"
      : status === "partial"
        ? "bg-high-wash text-high"
        : status === "failed" || status === "canceled"
          ? "bg-critical-wash text-critical"
          : "bg-brand-wash text-brand";
  const live = ["queued", "reconning", "running", "analyzing"].includes(status);
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium",
        tone,
      )}
    >
      {live && <span className="size-1.5 animate-pulse rounded-full bg-current" aria-hidden />}
      <span className="capitalize">{status}</span>
      {detail && <span className="opacity-70">· {detail}</span>}
    </span>
  );
}

// ---------------------------------------------------------------- Alerts / Empty / Spinner

export function Alert({
  tone = "info",
  children,
}: {
  tone?: "info" | "error" | "success";
  children: ReactNode;
}) {
  const cls =
    tone === "error"
      ? "border-critical/30 bg-critical-wash text-critical"
      : tone === "success"
        ? "border-ok/30 bg-ok-wash text-ok"
        : "border-brand/30 bg-brand-wash text-brand";
  return (
    <div
      role={tone === "error" ? "alert" : "status"}
      className={cx("rounded-control border px-3 py-2 text-sm", cls)}
    >
      {children}
    </div>
  );
}

export function Empty({
  title,
  body,
  action,
}: {
  title: string;
  body?: string | undefined;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center gap-2 py-10 text-center">
      <p className="font-medium text-ink">{title}</p>
      {body && <p className="max-w-sm text-sm text-muted">{body}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <div role="status" className="flex items-center gap-2 py-8 text-sm text-muted">
      <Loader2 className="size-4 animate-spin" aria-hidden /> {label}…
    </div>
  );
}
