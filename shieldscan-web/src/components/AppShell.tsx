/**
 * Authenticated layout: dark sidebar (navigation + plan line) and a
 * light content column — page map of the approved design v1.0. Routes
 * that are not built yet are listed but disabled, so navigation is
 * final from the first commit.
 */

import { NavLink, Outlet } from "react-router";
import {
  LayoutDashboard,
  FolderKanban,
  ShieldAlert,
  ClipboardCheck,
  Wrench,
  Settings,
  BookOpen,
  LogOut,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useAuth, useOrgId } from "@/lib/auth";
import { useOrgSummary } from "@/lib/queries";
import { cx } from "@/lib/cx";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  ready: boolean;
}

const NAV: NavItem[] = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard, ready: true },
  { to: "/projects", label: "Projects", icon: FolderKanban, ready: true },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert, ready: true },
  { to: "/compliance", label: "Compliance", icon: ClipboardCheck, ready: true },
  { to: "/tools", label: "Tool health", icon: Wrench, ready: true },
  { to: "/settings", label: "Settings", icon: Settings, ready: true },
];

export function AppShell() {
  const { me, signOut } = useAuth();
  const orgId = useOrgId();
  const summary = useOrgSummary(orgId);
  const openTotal = summary.data?.open_vulnerabilities.total;

  return (
    <div className="flex min-h-full">
      <aside className="flex w-60 shrink-0 flex-col bg-ink text-sidebar-text">
        <div className="flex items-center gap-2 px-5 py-5">
          <img src="/favicon.svg" alt="" className="size-6" />
          <span className="font-display text-lg font-semibold text-white">ShieldScan</span>
        </div>
        <div className="px-5 pb-4">
          <p className="truncate text-[11px] font-semibold uppercase tracking-wider text-muted">
            {me?.organization.name}
          </p>
        </div>
        <nav className="flex flex-1 flex-col gap-0.5 px-3" aria-label="Main">
          {NAV.map(({ to, label, icon: Icon, ready }) =>
            ready ? (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) =>
                  cx(
                    "flex items-center gap-3 rounded-control px-3 py-2 text-sm",
                    isActive ? "bg-ink-2 text-white" : "hover:bg-ink-2/60 hover:text-white",
                  )
                }
              >
                <Icon className="size-4" aria-hidden />
                <span className="flex-1">{label}</span>
                {label === "Vulnerabilities" && openTotal !== undefined && (
                  <span className="whitespace-nowrap rounded-full bg-ink-2 px-2 text-xs">
                    {openTotal} open
                  </span>
                )}
              </NavLink>
            ) : (
              <span
                key={to}
                aria-disabled="true"
                title="Coming in the next slice"
                className="flex cursor-not-allowed items-center gap-3 rounded-control px-3 py-2 text-sm opacity-50"
              >
                <Icon className="size-4" aria-hidden />
                <span className="flex-1">{label}</span>
                {label === "Vulnerabilities" && openTotal !== undefined && (
                  <span className="whitespace-nowrap rounded-full bg-ink-2 px-2 text-xs">
                    {openTotal} open
                  </span>
                )}
              </span>
            ),
          )}
          <a
            href="https://docs.shieldscan.io"
            target="_blank"
            rel="noreferrer"
            className="mt-2 flex items-center gap-3 rounded-control px-3 py-2 text-sm hover:bg-ink-2/60 hover:text-white"
          >
            <BookOpen className="size-4" aria-hidden /> API &amp; CLI docs
          </a>
        </nav>
        <div className="border-t border-ink-2 px-5 py-4 text-xs">
          <p className="text-sidebar-text">Free plan</p>
          <p className="mt-0.5 text-muted">Billing arrives with M12</p>
          <button
            type="button"
            onClick={() => void signOut()}
            className="mt-3 flex items-center gap-2 text-sidebar-text hover:text-white"
          >
            <LogOut className="size-4" aria-hidden /> Sign out
          </button>
        </div>
      </aside>
      <main className="min-w-0 flex-1 px-8 py-6">
        <Outlet />
      </main>
    </div>
  );
}
