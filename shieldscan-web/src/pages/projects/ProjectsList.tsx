/** /projects — every live target with its verification state. */

import { Link } from "react-router";
import { ShieldCheck, ShieldOff } from "lucide-react";
import { useOrgId } from "@/lib/auth";
import { useProjects } from "@/lib/queries";
import { hostOf, relTime } from "@/lib/format";
import { Alert, Button, Card, Empty, Spinner } from "@/components/ui";

export default function ProjectsList() {
  const orgId = useOrgId();
  const projects = useProjects(orgId);

  return (
    <div className="flex flex-col gap-6">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink">Projects</h1>
          <p className="mt-1 text-sm text-ink-3">
            A project is one target you own. Verify it once; scan it as often as your plan allows.
          </p>
        </div>
        <Link to="/projects/new">
          <Button>Add project</Button>
        </Link>
      </header>

      <Card>
        {projects.isPending ? (
          <Spinner />
        ) : projects.isError ? (
          <Alert tone="error">Couldn't load projects.</Alert>
        ) : projects.data.items.length === 0 ? (
          <Empty
            title="No projects yet"
            body="Add the site or API you want to test. You'll verify ownership with a DNS record, then run your first full scan."
            action={
              <Link to="/projects/new">
                <Button>Add your first project</Button>
              </Link>
            }
          />
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs font-medium uppercase tracking-wide text-ink-3">
                <th className="pb-2">Project</th>
                <th className="pb-2">Target</th>
                <th className="pb-2">Verification</th>
                <th className="pb-2 text-right">Added</th>
              </tr>
            </thead>
            <tbody>
              {projects.data.items.map((p) => (
                <tr key={p.id} className="border-t border-line-2">
                  <td className="py-3 font-medium text-ink">
                    <Link to={`/projects/${p.id}`} className="hover:text-brand">
                      {p.name}
                    </Link>
                  </td>
                  <td className="py-3 text-ink-3">{hostOf(p.target_url)}</td>
                  <td className="py-3">
                    {p.domain_verified ? (
                      <span className="inline-flex items-center gap-1 text-ok">
                        <ShieldCheck className="size-4" aria-hidden /> Verified
                      </span>
                    ) : (
                      <Link
                        to={`/projects/${p.id}#verify`}
                        className="inline-flex items-center gap-1 text-high hover:underline"
                      >
                        <ShieldOff className="size-4" aria-hidden /> Not verified — quick scans only
                      </Link>
                    )}
                  </td>
                  <td className="py-3 text-right text-ink-3">{relTime(p.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
