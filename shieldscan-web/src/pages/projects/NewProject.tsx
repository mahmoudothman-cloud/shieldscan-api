/** /projects/new — name + target URL (+ optional source repo / image). */

import { useState } from "react";
import type { FormEvent } from "react";
import { Link, useNavigate } from "react-router";
import { useOrgId } from "@/lib/auth";
import { useCreateProject } from "@/lib/queries";
import { ApiError } from "@/lib/api";
import { Alert, Button, Card, Field, Input } from "@/components/ui";

export default function NewProject() {
  const orgId = useOrgId();
  const navigate = useNavigate();
  const create = useCreateProject(orgId);
  const [name, setName] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [repo, setRepo] = useState("");
  const [image, setImage] = useState("");

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    let url = targetUrl.trim();
    if (url && !/^https?:\/\//i.test(url)) url = `https://${url}`;
    const project = await create.mutateAsync({
      name: name.trim() || hostOfSafe(url),
      target_url: url,
      source_repo_url: repo.trim() || null,
      container_image: image.trim() || null,
    });
    void navigate(`/projects/${project.id}#verify`);
  }

  const errorText =
    create.error instanceof ApiError
      ? create.error.status === 422
        ? "That target URL doesn't look right. Use the site's public https:// address."
        : String(create.error.detail ?? "Couldn't create the project.")
      : null;

  return (
    <div className="mx-auto flex max-w-xl flex-col gap-6">
      <header>
        <Link to="/projects" className="text-sm text-brand">
          ← Projects
        </Link>
        <h1 className="mt-2 text-2xl font-semibold text-ink">Add a project</h1>
        <p className="mt-1 text-sm text-ink-3">
          Only scan what you own or have written permission to test (Egypt Law 175/2018). You'll
          prove ownership next.
        </p>
      </header>
      <Card>
        <form onSubmit={onSubmit} className="flex flex-col gap-4" noValidate>
          {errorText && <Alert tone="error">{errorText}</Alert>}
          <Field
            label="Target URL"
            hint="The public address users visit, e.g. https://shop.example.com"
          >
            {(id, by) => (
              <Input
                id={id}
                type="url"
                required
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                aria-describedby={by}
                placeholder="https://"
              />
            )}
          </Field>
          <Field label="Project name" hint="Defaults to the hostname.">
            {(id, by) => (
              <Input
                id={id}
                value={name}
                onChange={(e) => setName(e.target.value)}
                aria-describedby={by}
              />
            )}
          </Field>
          <details className="rounded-control border border-line p-3">
            <summary className="cursor-pointer text-sm font-medium text-ink">
              Optional: source code and container image
            </summary>
            <div className="mt-3 flex flex-col gap-4">
              <Field
                label="Git repository URL"
                hint="Unlocks SAST, secret scanning and dependency checks (full web + source)."
              >
                {(id, by) => (
                  <Input
                    id={id}
                    type="url"
                    value={repo}
                    onChange={(e) => setRepo(e.target.value)}
                    aria-describedby={by}
                    placeholder="https://github.com/org/repo"
                  />
                )}
              </Field>
              <Field
                label="Container image"
                hint="e.g. ghcr.io/org/app:1.4.2 — scanned with Trivy."
              >
                {(id, by) => (
                  <Input
                    id={id}
                    value={image}
                    onChange={(e) => setImage(e.target.value)}
                    aria-describedby={by}
                  />
                )}
              </Field>
            </div>
          </details>
          <div className="flex justify-end gap-2">
            <Link to="/projects">
              <Button type="button" variant="secondary">
                Cancel
              </Button>
            </Link>
            <Button type="submit" loading={create.isPending}>
              Create project
            </Button>
          </div>
        </form>
      </Card>
    </div>
  );
}

function hostOfSafe(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}
