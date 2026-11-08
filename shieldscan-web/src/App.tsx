/**
 * Route table — the page map of the approved design v1.0. Public routes
 * render without a session; everything under <RequireAuth> waits for
 * the boot refresh and redirects to /login (keeping `next`) when there
 * is no session. Pages are lazy so the auth bundle stays small.
 */

import { Suspense, lazy } from "react";
import { Navigate, Outlet, Route, Routes, useLocation } from "react-router";
import { useAuth } from "@/lib/auth";
import { AppShell } from "@/components/AppShell";
import { Spinner } from "@/components/ui";

const Login = lazy(() => import("@/pages/auth/Login"));
const Register = lazy(() => import("@/pages/auth/Register"));
const VerifyEmail = lazy(() => import("@/pages/auth/VerifyEmail"));
const ForgotPassword = lazy(() => import("@/pages/auth/ForgotPassword"));
const ResetPassword = lazy(() => import("@/pages/auth/ResetPassword"));
const Dashboard = lazy(() => import("@/pages/Dashboard"));
const ProjectsList = lazy(() => import("@/pages/projects/ProjectsList"));
const NewProject = lazy(() => import("@/pages/projects/NewProject"));
const ProjectDetail = lazy(() => import("@/pages/projects/ProjectDetail"));
const ScanRun = lazy(() => import("@/pages/scans/ScanRun"));
const VulnerabilitiesList = lazy(() => import("@/pages/vulnerabilities/VulnerabilitiesList"));
const VulnerabilityDetail = lazy(() => import("@/pages/vulnerabilities/VulnerabilityDetail"));

function RequireAuth() {
  const { status } = useAuth();
  const location = useLocation();
  if (status === "booting") return <Spinner label="Signing you in" />;
  if (status === "anonymous") {
    const next = encodeURIComponent(location.pathname + location.search);
    return <Navigate to={`/login?next=${next}`} replace />;
  }
  return <Outlet />;
}

function RedirectIfAuthed({ children }: { children: React.ReactNode }) {
  const { status } = useAuth();
  if (status === "authenticated") return <Navigate to="/dashboard" replace />;
  return <>{children}</>;
}

function NotFound() {
  return (
    <div className="p-10 text-center text-sm text-ink-3">
      <p className="font-display text-3xl text-ink">404</p>
      <p className="mt-2">There's nothing at this address.</p>
    </div>
  );
}

export default function App() {
  return (
    <Suspense fallback={<Spinner />}>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />

        <Route
          path="/login"
          element={
            <RedirectIfAuthed>
              <Login />
            </RedirectIfAuthed>
          }
        />
        <Route
          path="/register"
          element={
            <RedirectIfAuthed>
              <Register />
            </RedirectIfAuthed>
          }
        />
        <Route path="/verify-email" element={<VerifyEmail />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset-password" element={<ResetPassword />} />
        <Route path="/accept-invite" element={<ResetPassword invite />} />

        <Route element={<RequireAuth />}>
          <Route element={<AppShell />}>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/projects" element={<ProjectsList />} />
            <Route path="/projects/new" element={<NewProject />} />
            <Route path="/projects/:projectId" element={<ProjectDetail />} />
            <Route path="/scans/:scanId" element={<ScanRun />} />
            <Route path="/vulnerabilities" element={<VulnerabilitiesList />} />
            <Route path="/vulnerabilities/:vid" element={<VulnerabilityDetail />} />
          </Route>
        </Route>

        <Route path="*" element={<NotFound />} />
      </Routes>
    </Suspense>
  );
}
