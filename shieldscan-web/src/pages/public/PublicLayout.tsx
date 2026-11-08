/** Header/footer for the unauthenticated pages (landing, quick-scan result). */

import type { ReactNode } from "react";
import { Link } from "react-router";
import { useAuth } from "@/lib/auth";

export function PublicLayout({ children }: { children: ReactNode }) {
  const { status } = useAuth();
  return (
    <div className="flex min-h-full flex-col bg-wash">
      <header className="border-b border-line bg-paper">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
          <Link to="/" className="flex items-center gap-2">
            <img src="/favicon.svg" alt="" className="size-6" />
            <span className="font-display text-lg font-semibold text-ink">ShieldScan</span>
          </Link>
          <nav className="flex items-center gap-4 text-sm">
            <a href="#how" className="hidden text-ink-3 hover:text-ink sm:inline">
              How it works
            </a>
            {status === "authenticated" ? (
              <Link
                to="/dashboard"
                className="rounded-control bg-brand px-3 py-1.5 font-medium text-white"
              >
                Dashboard
              </Link>
            ) : (
              <>
                <Link to="/login" className="text-ink-3 hover:text-ink">
                  Sign in
                </Link>
                <Link
                  to="/register"
                  className="rounded-control bg-brand px-3 py-1.5 font-medium text-white"
                >
                  Create account
                </Link>
              </>
            )}
          </nav>
        </div>
      </header>
      <main className="mx-auto w-full max-w-5xl flex-1 px-4 py-10">{children}</main>
      <footer className="border-t border-line bg-paper">
        <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-2 px-4 py-4 text-xs text-ink-3">
          <span>© 2026 Odyssey Technology · Cairo · hosted under EU-adequacy rules</span>
          <span>
            Scans originate from <code className="font-mono">144.217.27.177</code> — allow-list it
            if you need to.
          </span>
        </div>
      </footer>
    </div>
  );
}
