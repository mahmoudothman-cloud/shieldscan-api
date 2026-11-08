/**
 * /quick-scan (and / for anonymous visitors) — the free passive check
 * that starts flow F1. Copy from the approved design v1.0, timing and
 * check list adjusted to what the public endpoint actually runs today
 * (nuclei misconfig/exposure/ssl/dns/tech + sslyze, ~2 minutes).
 */

import { useState } from "react";
import type { FormEvent } from "react";
import { useNavigate } from "react-router";
import { useCreateQuickScan } from "@/lib/queries";
import { ApiError } from "@/lib/api";
import { Alert, Button, Field, Input } from "@/components/ui";
import { PublicLayout } from "./PublicLayout";

export default function QuickScanLanding() {
  const navigate = useNavigate();
  const create = useCreateQuickScan();
  const [url, setUrl] = useState("");
  const [email, setEmail] = useState("");
  const [consent, setConsent] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (!consent) return;
    const res = await create.mutateAsync({
      target_url: url.trim(),
      email: email.trim(),
      consent: true,
    });
    void navigate(`/q/${res.slug}`);
  }

  const err =
    create.error instanceof ApiError
      ? create.error.detail === "email_limit_reached"
        ? "That address already ran its free scan today. The result link is in your inbox — or create an account for more."
        : create.error.detail === "rate_limited"
          ? "Too many scans from this network in the last hour. Try again later."
          : create.error.status === 422
            ? "Use the site's public https:// address and a work email."
            : "Couldn't start the scan. Please try again."
      : null;

  return (
    <PublicLayout>
      <section className="grid items-start gap-10 lg:grid-cols-2">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-brand">
            Built in Cairo · read-only probes
          </p>
          <h1 className="mt-2 text-4xl font-semibold leading-tight text-ink">
            Find out what an attacker sees. In about two minutes, free.
          </h1>
          <p className="mt-4 text-base text-ink-3">
            A passive check of your security headers, TLS and certificate, exposed files and
            consoles, and the technology you reveal — explained in plain language. Then, when you
            are ready, the full scan: 14 engines, findings corroborated across them, with the fix.
          </p>
          <ul className="mt-6 flex flex-col gap-2 text-sm text-ink-3">
            <li>• No account, no agent, no code access. One scan per email per day.</li>
            <li>
              • Same requests a browser makes — nothing is sent to your app that could break it.
            </li>
            <li>• Results page is private to your link and expires in 7 days.</li>
          </ul>
        </div>

        <form
          onSubmit={onSubmit}
          className="rounded-card border border-line bg-paper p-6 shadow-sm"
          noValidate
        >
          <h2 className="text-lg font-semibold text-ink">Run a free quick scan</h2>
          <div className="mt-4 flex flex-col gap-4">
            {err && <Alert tone="error">{err}</Alert>}
            <Field label="Your app URL">
              {(id) => (
                <Input
                  id={id}
                  type="url"
                  required
                  placeholder="https://app.example.com"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                />
              )}
            </Field>
            <Field label="Work email" hint="The report link goes here.">
              {(id, by) => (
                <Input
                  id={id}
                  type="email"
                  required
                  autoComplete="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  aria-describedby={by}
                />
              )}
            </Field>
            <label className="flex items-start gap-2 text-sm text-ink-3">
              <input
                type="checkbox"
                className="mt-1"
                checked={consent}
                onChange={(e) => setConsent(e.target.checked)}
                required
              />
              <span>
                I own this domain or have written permission to scan it (Egypt Law 175/2018 and the
                laws of the target's jurisdiction). Probes are read-only.
              </span>
            </label>
            <Button type="submit" disabled={!consent} loading={create.isPending} className="w-full">
              Scan now — results in about two minutes
            </Button>
            <p className="text-center text-xs text-ink-3">
              Free · no card · results page expires in 7 days
            </p>
          </div>
        </form>
      </section>

      <section id="how" className="mt-16 grid gap-6 md:grid-cols-3">
        <Tier
          eyebrow="Quick · ~2 min · free"
          title="Passive, from the outside"
          body="Security headers, TLS and certificate, exposed files and admin consoles, technology fingerprints. Graded A–F."
        />
        <Tier
          eyebrow="Full · 5–20 min"
          title="Active, with proof"
          body="Nuclei, ZAP, Wapiti, Nikto, SQLMap confirmation and more, after you verify you own the domain. Findings seen by two engines get a corroborated badge."
        />
        <Tier
          eyebrow="Code · optional"
          title="Source, dependencies, IaC"
          body="Connect a repo for Semgrep, Gitleaks, Trivy and Checkov — and DAST↔SAST correlation that tells you which line caused the finding."
        />
      </section>

      <section className="mt-16 text-center">
        <h2 className="text-2xl font-semibold text-ink">Eight categories. One report.</h2>
        <p className="mx-auto mt-2 max-w-2xl text-sm text-ink-3">
          A two-minute check finds the doors left open. The full scan finds the ones that are
          picked. Both are explained the same way: what it is, why it matters to your business,
          exactly how to fix it.
        </p>
        <div className="mt-6 flex flex-wrap justify-center gap-2">
          {["DAST", "SAST", "SCA", "API", "Infra", "Container", "Secrets", "IaC"].map((c) => (
            <span
              key={c}
              className="rounded-full border border-line bg-paper px-3 py-1 text-xs font-medium text-ink-3"
            >
              {c}
            </span>
          ))}
        </div>
      </section>
    </PublicLayout>
  );
}

function Tier({ eyebrow, title, body }: { eyebrow: string; title: string; body: string }) {
  return (
    <div className="rounded-card border border-line bg-paper p-5">
      <p className="text-xs font-semibold uppercase tracking-wider text-brand">{eyebrow}</p>
      <h3 className="mt-1 text-base font-semibold text-ink">{title}</h3>
      <p className="mt-2 text-sm text-ink-3">{body}</p>
    </div>
  );
}
