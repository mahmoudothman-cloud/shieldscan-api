/**
 * /settings — organization profile, members, API keys. Admin-only
 * controls are rendered disabled (not hidden) for members and viewers,
 * with the reason, so the shape of the page is the same for everyone.
 * Billing (M12) and notifications will add tabs here.
 */

import { useState } from "react";
import { Link } from "react-router";
import type { FormEvent } from "react";
import { Check, Copy, KeyRound, Trash2 } from "lucide-react";
import { useAuth, useOrgId } from "@/lib/auth";
import {
  useApiKeys,
  useChangeMemberRole,
  useCreateApiKey,
  useInviteMember,
  useMembers,
  useOrg,
  useRemoveMember,
  useRevokeApiKey,
  useUpdateOrg,
} from "@/lib/queries";
import { ApiError } from "@/lib/api";
import type { MemberItem, OrgResponse } from "@/lib/types";
import { relTime } from "@/lib/format";
import { PlanLimitAlert } from "@/components/PlanLimitAlert";
import { Alert, Button, Card, Field, Input, Select, Spinner } from "@/components/ui";
import { planLimitOf } from "@/lib/plan";
import { BillingCard } from "@/pages/settings/BillingCard";
import { PlanUsage } from "@/pages/settings/PlanUsage";

const ROLES: Array<{ value: MemberItem["role"]; label: string; blurb: string }> = [
  { value: "admin", label: "Admin", blurb: "Everything, including members, API keys and billing." },
  { value: "member", label: "Member", blurb: "Projects, scans and vulnerability triage." },
  { value: "viewer", label: "Viewer", blurb: "Read-only: dashboards, findings and reports." },
];

export default function Settings() {
  const orgId = useOrgId();
  const org = useOrg(orgId);
  const { me } = useAuth();
  if (org.isPending) return <Spinner label="Loading settings" />;
  if (org.isError) return <Alert tone="error">Couldn't load organization settings.</Alert>;
  const isAdmin = org.data.my_role === "admin";

  return (
    <div className="flex flex-col gap-6">
      <header>
        <h1 className="text-2xl font-semibold text-ink">Settings</h1>
        <p className="mt-1 text-sm text-ink-3">
          {org.data.name} · you are {org.data.my_role ?? "an API key"}
          {!isAdmin && " · ask an admin to change what is greyed out"}
        </p>
      </header>
      <div className="grid gap-6 lg:grid-cols-2">
        <div className="lg:col-span-2">
          <BillingCard orgId={orgId} isAdmin={isAdmin} />
        </div>
        <div className="lg:col-span-2">
          <PlanUsage orgId={orgId} />
        </div>
        {me?.user?.is_platform_admin && (
          <Card title="Platform admin" className="lg:col-span-2">
            <p className="text-sm text-ink-3">
              Edit the plan catalog, publish new versions, and manage any organization's
              subscription and overrides.{" "}
              <Link to="/admin/plans" className="text-brand underline">
                Plans
              </Link>{" "}
              ·{" "}
              <Link to="/admin/orgs" className="text-brand underline">
                Organizations
              </Link>
            </p>
          </Card>
        )}
        <OrgProfile org={org.data} isAdmin={isAdmin} />
        <ApiKeys isAdmin={isAdmin} />
        <div className="lg:col-span-2">
          <Members orgId={orgId} isAdmin={isAdmin} />
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- org profile

function OrgProfile({ org, isAdmin }: { org: OrgResponse; isAdmin: boolean }) {
  const orgId = useOrgId();
  const update = useUpdateOrg(orgId);
  const [form, setForm] = useState({
    name: org.name,
    industry: org.industry ?? "",
    country: org.country ?? "",
    company_size: org.company_size ?? "",
  });
  const dirty =
    form.name !== org.name ||
    form.industry !== (org.industry ?? "") ||
    form.country !== (org.country ?? "") ||
    form.company_size !== (org.company_size ?? "");

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    update.mutate({
      name: form.name.trim(),
      industry: form.industry.trim() || null,
      country: form.country.trim() || null,
      company_size: form.company_size.trim() || null,
    });
  }

  return (
    <Card title="Organization">
      <form onSubmit={onSubmit} className="flex flex-col gap-4" noValidate>
        <Field label="Name">
          {(id) => (
            <Input
              id={id}
              value={form.name}
              disabled={!isAdmin}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              required
            />
          )}
        </Field>
        <div className="grid gap-4 sm:grid-cols-3">
          <Field label="Industry" hint="Used for peer benchmarks.">
            {(id, by) => (
              <Select
                id={id}
                aria-describedby={by}
                value={form.industry}
                disabled={!isAdmin}
                onChange={(e) => setForm({ ...form, industry: e.target.value })}
              >
                <option value="">—</option>
                {[
                  "fintech",
                  "ecommerce",
                  "healthcare",
                  "education",
                  "government",
                  "saas",
                  "media",
                  "logistics",
                  "other",
                ].map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Country" hint="ISO code, e.g. EG">
            {(id, by) => (
              <Input
                id={id}
                aria-describedby={by}
                value={form.country}
                maxLength={2}
                disabled={!isAdmin}
                onChange={(e) => setForm({ ...form, country: e.target.value.toUpperCase() })}
              />
            )}
          </Field>
          <Field label="Company size">
            {(id) => (
              <Select
                id={id}
                value={form.company_size}
                disabled={!isAdmin}
                onChange={(e) => setForm({ ...form, company_size: e.target.value })}
              >
                <option value="">—</option>
                {["1-10", "11-50", "51-200", "201-1000", "1000+"].map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>
        <p className="text-xs text-ink-3">
          Slug <code className="font-mono">{org.slug}</code> is fixed · {org.member_count}{" "}
          {org.member_count === 1 ? "member" : "members"}
        </p>
        {update.isError && (
          <Alert tone="error">
            Couldn't save.{" "}
            {update.error instanceof ApiError && update.error.status === 403
              ? "Only admins can edit the organization."
              : ""}
          </Alert>
        )}
        {update.isSuccess && !dirty && <Alert tone="success">Saved.</Alert>}
        <div className="flex justify-end">
          <Button type="submit" disabled={!isAdmin || !dirty} loading={update.isPending}>
            Save changes
          </Button>
        </div>
      </form>
    </Card>
  );
}

// ---------------------------------------------------------------- members

function Members({ orgId, isAdmin }: { orgId: string; isAdmin: boolean }) {
  const { me } = useAuth();
  const members = useMembers(orgId);
  const invite = useInviteMember(orgId);
  const changeRole = useChangeMemberRole(orgId);
  const remove = useRemoveMember(orgId);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<MemberItem["role"]>("member");
  const [lastInvite, setLastInvite] = useState<string | null>(null);
  const [confirmRemove, setConfirmRemove] = useState<string | null>(null);

  async function onInvite(e: FormEvent) {
    e.preventDefault();
    const res = await invite.mutateAsync({ email: email.trim(), role });
    setLastInvite(
      res.invited_new_user
        ? `Invitation sent to ${res.email}. They set a password from the link.`
        : `${res.email} already had an account and was added directly.`,
    );
    setEmail("");
  }

  const inviteLimit = planLimitOf(invite.error);
  const inviteError =
    inviteLimit === null && invite.error instanceof ApiError
      ? invite.error.detail === "already_member"
        ? "That person is already a member."
        : invite.error.status === 403
          ? "Only admins signed in with a password can invite."
          : "Couldn't send the invitation."
      : null;
  const roleError =
    changeRole.error instanceof ApiError && changeRole.error.detail === "last_admin"
      ? "An organization needs at least one admin."
      : null;
  const removeError =
    remove.error instanceof ApiError && remove.error.detail === "last_admin"
      ? "You can't remove the only admin."
      : null;

  return (
    <Card title="Members">
      <div className="flex flex-col gap-5">
        {isAdmin && (
          <form
            onSubmit={onInvite}
            className="flex flex-wrap items-end gap-3 rounded-control bg-wash p-3"
            noValidate
          >
            <div className="min-w-56 flex-1">
              <Field label="Invite by work email">
                {(id) => (
                  <Input
                    id={id}
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="colleague@company.com"
                  />
                )}
              </Field>
            </div>
            <div className="w-40">
              <Field label="Role">
                {(id) => (
                  <Select
                    id={id}
                    value={role}
                    onChange={(e) => setRole(e.target.value as MemberItem["role"])}
                  >
                    {ROLES.map((r) => (
                      <option key={r.value} value={r.value}>
                        {r.label}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
            </div>
            <Button type="submit" loading={invite.isPending}>
              Send invite
            </Button>
            <p className="basis-full text-xs text-ink-3">
              {ROLES.find((r) => r.value === role)?.blurb}
            </p>
          </form>
        )}
        {inviteLimit && <PlanLimitAlert limit={inviteLimit} />}
        {inviteError && <Alert tone="error">{inviteError}</Alert>}
        {lastInvite && !invite.isError && <Alert tone="success">{lastInvite}</Alert>}
        {(roleError || removeError) && <Alert tone="error">{roleError ?? removeError}</Alert>}

        {members.isPending ? (
          <Spinner />
        ) : members.isError ? (
          <Alert tone="error">Couldn't load members.</Alert>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs font-medium uppercase tracking-wide text-ink-3">
                <th className="pb-2">Person</th>
                <th className="pb-2">Role</th>
                <th className="pb-2">Status</th>
                <th className="pb-2 text-right">Joined</th>
                <th className="pb-2" />
              </tr>
            </thead>
            <tbody>
              {members.data.map((m) => {
                const isSelf = me?.user?.id === m.user_id;
                return (
                  <tr key={m.user_id} className="border-t border-line-2">
                    <td className="py-2.5">
                      <p className="font-medium text-ink">
                        {m.full_name}
                        {isSelf ? " (you)" : ""}
                      </p>
                      <p className="text-xs text-ink-3">{m.email}</p>
                    </td>
                    <td className="py-2.5">
                      {isAdmin ? (
                        <Select
                          aria-label={`Role for ${m.email}`}
                          value={m.role}
                          className="h-8 w-32 text-xs"
                          onChange={(e) =>
                            changeRole.mutate({
                              userId: m.user_id,
                              role: e.target.value as MemberItem["role"],
                            })
                          }
                        >
                          {ROLES.map((r) => (
                            <option key={r.value} value={r.value}>
                              {r.label}
                            </option>
                          ))}
                        </Select>
                      ) : (
                        <span className="capitalize text-ink">{m.role}</span>
                      )}
                    </td>
                    <td className="py-2.5 text-ink-3">
                      {m.email_verified ? "Active" : "Invited — not verified"}
                    </td>
                    <td className="py-2.5 text-right text-ink-3">{relTime(m.joined_at)}</td>
                    <td className="py-2.5 text-right">
                      {isAdmin &&
                        (confirmRemove === m.user_id ? (
                          <span className="inline-flex items-center gap-2 text-xs">
                            <span className="text-ink-3">Remove?</span>
                            <Button
                              size="sm"
                              variant="secondary"
                              onClick={() => setConfirmRemove(null)}
                            >
                              Keep
                            </Button>
                            <Button
                              size="sm"
                              variant="danger"
                              loading={remove.isPending}
                              onClick={() =>
                                void remove
                                  .mutateAsync(m.user_id)
                                  .finally(() => setConfirmRemove(null))
                              }
                            >
                              Remove
                            </Button>
                          </span>
                        ) : (
                          <button
                            type="button"
                            aria-label={`Remove ${m.email}`}
                            className="rounded p-1 text-ink-3 hover:bg-critical-wash hover:text-critical"
                            onClick={() => setConfirmRemove(m.user_id)}
                          >
                            <Trash2 className="size-4" aria-hidden />
                          </button>
                        ))}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------- API keys

function ApiKeys({ isAdmin }: { isAdmin: boolean }) {
  const list = useApiKeys();
  const create = useCreateApiKey();
  const keyLimit = planLimitOf(create.error);
  const revoke = useRevokeApiKey();
  const [name, setName] = useState("");
  const [copied, setCopied] = useState(false);
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);
  const fresh = create.data;

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    await create.mutateAsync(name.trim());
    setName("");
  }

  return (
    <Card title="API keys" action={<KeyRound className="size-4 text-ink-3" aria-hidden />}>
      <div className="flex flex-col gap-4">
        <p className="text-sm text-ink-3">
          For CI, the CLI and the MCP server. A key acts with admin rights inside this organization;
          it cannot invite or remove people.
        </p>
        {isAdmin && (
          <form onSubmit={onCreate} className="flex items-end gap-3" noValidate>
            <div className="flex-1">
              <Field label="New key name">
                {(id) => (
                  <Input
                    id={id}
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="GitHub Actions — main"
                  />
                )}
              </Field>
            </div>
            <Button type="submit" loading={create.isPending}>
              Create key
            </Button>
          </form>
        )}
        {keyLimit && <PlanLimitAlert limit={keyLimit} />}
        {create.isError && !keyLimit && <Alert tone="error">Couldn't create the key.</Alert>}
        {fresh && (
          <div className="rounded-control border border-brand/40 bg-brand-wash p-3 text-sm">
            <p className="font-medium text-ink">Copy this key now — it is shown once.</p>
            <div className="mt-2 flex items-center gap-2">
              <code className="min-w-0 flex-1 break-all rounded bg-paper px-2 py-1 font-mono text-xs text-ink">
                {fresh.plaintext_key}
              </code>
              <button
                type="button"
                aria-label="Copy API key"
                className="rounded p-1 text-ink-3 hover:bg-paper hover:text-ink"
                onClick={() =>
                  void navigator.clipboard?.writeText(fresh.plaintext_key).then(() => {
                    setCopied(true);
                    setTimeout(() => setCopied(false), 1500);
                  })
                }
              >
                {copied ? (
                  <Check className="size-4 text-ok" aria-hidden />
                ) : (
                  <Copy className="size-4" aria-hidden />
                )}
              </button>
            </div>
            <p className="mt-2 text-xs text-ink-3">
              Use it as <code className="font-mono">Authorization: Bearer &lt;key&gt;</code>.
            </p>
          </div>
        )}
        {list.isPending ? (
          <Spinner />
        ) : list.isError ? (
          <Alert tone="error">
            {list.error instanceof ApiError && list.error.status === 403
              ? "Only admins can see API keys."
              : "Couldn't load API keys."}
          </Alert>
        ) : list.data.length === 0 ? (
          <p className="text-sm text-ink-3">No keys yet.</p>
        ) : (
          <ul className="divide-y divide-line-2 text-sm">
            {list.data.map((k) => (
              <li key={k.id} className="flex items-center gap-3 py-2">
                <div className="min-w-0 flex-1">
                  <p className={k.revoked_at ? "text-ink-3 line-through" : "font-medium text-ink"}>
                    {k.name}
                  </p>
                  <p className="font-mono text-xs text-ink-3">
                    {k.key_prefix}… ·{" "}
                    {k.revoked_at
                      ? `revoked ${relTime(k.revoked_at)}`
                      : k.last_used_at
                        ? `last used ${relTime(k.last_used_at)}`
                        : "never used"}
                  </p>
                </div>
                {isAdmin &&
                  !k.revoked_at &&
                  (confirmRevoke === k.id ? (
                    <span className="inline-flex items-center gap-2 text-xs">
                      <Button size="sm" variant="secondary" onClick={() => setConfirmRevoke(null)}>
                        Keep
                      </Button>
                      <Button
                        size="sm"
                        variant="danger"
                        loading={revoke.isPending}
                        onClick={() =>
                          void revoke.mutateAsync(k.id).finally(() => setConfirmRevoke(null))
                        }
                      >
                        Revoke
                      </Button>
                    </span>
                  ) : (
                    <Button size="sm" variant="ghost" onClick={() => setConfirmRevoke(k.id)}>
                      Revoke
                    </Button>
                  ))}
              </li>
            ))}
          </ul>
        )}
      </div>
    </Card>
  );
}
