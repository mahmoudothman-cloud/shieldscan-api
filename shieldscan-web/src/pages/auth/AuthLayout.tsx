/** Centered card layout shared by every public auth page. */

import type { ReactNode } from "react";
import { Link } from "react-router";

export function AuthLayout({
  title,
  lede,
  children,
  footer,
}: {
  title: string;
  lede?: string | undefined;
  children: ReactNode;
  footer?: ReactNode | undefined;
}) {
  return (
    <div className="flex min-h-full flex-col items-center justify-center bg-wash px-4 py-10">
      <Link to="/" className="mb-6 flex items-center gap-2">
        <img src="/favicon.svg" alt="" className="size-7" />
        <span className="font-display text-xl font-semibold text-ink">ShieldScan</span>
      </Link>
      <div className="w-full max-w-md rounded-card border border-line bg-paper p-8 shadow-sm">
        <h1 className="text-xl font-semibold text-ink">{title}</h1>
        {lede && <p className="mt-1 text-sm text-ink-3">{lede}</p>}
        <div className="mt-6">{children}</div>
      </div>
      {footer && <p className="mt-4 text-sm text-ink-3">{footer}</p>}
    </div>
  );
}
