import { useEffect, useState } from "react";
import {
  listServiceAccounts,
  createServiceAccount,
  rotateServiceAccount,
  revokeServiceAccount,
  type ServiceAccount,
} from "../../api";
import { PageHeader } from "../ui/PageHeader";
import { Card } from "../ui/Card";
import { Button } from "../ui/Button";
import { Input, Select } from "../ui/Input";
import { Badge, type BadgeVariant } from "../ui/Badge";
import "./ServiceAccounts.scss";

// Bindable roles match the server allowlist: operational roles only, never a management-capable role.
const ROLES = [
  { value: "analyst", label: "Analyst" },
  { value: "senior_analyst", label: "Senior analyst" },
  { value: "auditor", label: "Auditor" },
] as const;

function statusVariant(status: string): BadgeVariant {
  switch (status) {
    case "active":
      return "success";
    case "revoked":
      return "critical";
    default:
      return "neutral"; // expired
  }
}

function roleVariant(role: string): BadgeVariant {
  switch (role) {
    case "senior_analyst":
      return "info";
    case "auditor":
      return "success";
    default:
      return "neutral";
  }
}

function roleLabel(role: string): string {
  return ROLES.find((r) => r.value === role)?.label ?? role;
}

function formatDate(s?: string): string {
  if (!s) return "Never";
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? s : d.toLocaleDateString();
}

// IssuedSecret is the one-time credential shown after a create or rotate; it is never retrievable again.
interface IssuedSecret {
  name: string;
  clientID: string;
  secret: string;
}

export function ServiceAccounts() {
  const [accounts, setAccounts] = useState<ServiceAccount[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState("");
  const [role, setRole] = useState<string>(ROLES[0].value);
  const [expiresInDays, setExpiresInDays] = useState("");
  const [creating, setCreating] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const [issued, setIssued] = useState<IssuedSecret | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busyID, setBusyID] = useState<number | null>(null);
  const [confirmRevokeID, setConfirmRevokeID] = useState<number | null>(null);

  function reload(): void {
    listServiceAccounts()
      .then((rows) => { setAccounts(rows); })
      .catch((err: unknown) => { setError(err instanceof Error ? err.message : "Failed to load service accounts"); });
  }

  useEffect(() => {
    let cancelled = false;
    listServiceAccounts()
      .then((rows) => { if (!cancelled) setAccounts(rows); })
      .catch((err: unknown) => { if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load service accounts"); });
    return () => { cancelled = true; };
  }, []);

  async function handleCreate() {
    const trimmed = name.trim();
    if (trimmed === "") {
      setFormError("Name is required.");
      return;
    }
    setCreating(true);
    setFormError(null);
    try {
      const days = expiresInDays.trim() === "" ? undefined : Number(expiresInDays);
      const created = await createServiceAccount({
        name: trimmed,
        role,
        ...(days !== undefined && Number.isFinite(days) ? { expires_in_days: days } : {}),
      });
      setIssued({ name: created.name, clientID: created.client_id, secret: created.secret });
      setName("");
      setExpiresInDays("");
      setRole(ROLES[0].value);
      setShowCreate(false);
      reload();
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : "Failed to create service account.");
    } finally {
      setCreating(false);
    }
  }

  async function handleRotate(sa: ServiceAccount) {
    setBusyID(sa.id);
    setActionError(null);
    try {
      const { secret } = await rotateServiceAccount(sa.id);
      setIssued({ name: sa.name, clientID: sa.client_id, secret });
      reload();
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : "Failed to rotate secret.");
    } finally {
      setBusyID(null);
    }
  }

  async function handleRevoke(sa: ServiceAccount) {
    setBusyID(sa.id);
    setActionError(null);
    try {
      await revokeServiceAccount(sa.id);
      setConfirmRevokeID(null);
      reload();
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : "Failed to revoke service account.");
    } finally {
      setBusyID(null);
    }
  }

  async function copySecret(secret: string) {
    const clipboard = navigator.clipboard as Clipboard | undefined;
    if (!clipboard) return;
    try {
      await clipboard.writeText(secret);
    } catch {
      // Clipboard unavailable (insecure context); the field is selectable as a fallback.
    }
  }

  return (
    <div className="service-accounts">
      <PageHeader
        title="Service accounts"
        subtitle="Non-human identities (CI, integrations, scripts) that authenticate to the API with a client credential and carry a role."
        actions={
          <Button type="button" variant="primary" onClick={() => { setShowCreate((v) => !v); }}>
            Create service account
          </Button>
        }
      />

      {issued !== null && (
        <Card padding="large" className="service-accounts__secret" role="status">
          <h2 className="service-accounts__secret-title">Save this secret now</h2>
          <p className="service-accounts__help">
            This is the only time the secret for <strong>{issued.name}</strong> is shown. Store it in your secret manager; it cannot be
            retrieved again.
          </p>
          <div className="service-accounts__field">
            <span className="field__label">Client ID</span>
            <input className="field__input service-accounts__mono" type="text" readOnly aria-label="Client ID" value={issued.clientID} />
          </div>
          <div className="service-accounts__field">
            <span className="field__label">Client secret</span>
            <div className="service-accounts__secret-row">
              <input className="field__input service-accounts__mono" type="text" readOnly aria-label="Client secret" value={issued.secret} />
              <Button type="button" variant="inverse" size="small" onClick={() => { void copySecret(issued.secret); }}>
                Copy
              </Button>
            </div>
          </div>
          <div className="service-accounts__footer">
            <Button type="button" variant="primary" size="small" onClick={() => { setIssued(null); }}>
              Done
            </Button>
          </div>
        </Card>
      )}

      {showCreate && (
        <Card padding="large">
          <h2 className="service-accounts__card-title">New service account</h2>
          <div className="service-accounts__form">
            <Input
              id="sa-name"
              label="Name"
              type="text"
              placeholder="ci-pipeline"
              value={name}
              onChange={(e) => { setName(e.target.value); }}
            />
            <Select id="sa-role" label="Role" value={role} onChange={(e) => { setRole(e.target.value); }} inline={false}>
              {ROLES.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
            </Select>
            <Input
              id="sa-expires"
              label="Expires in (days)"
              type="number"
              min={1}
              max={365}
              placeholder="90"
              value={expiresInDays}
              onChange={(e) => { setExpiresInDays(e.target.value); }}
            />
          </div>
          <p className="service-accounts__help">Defaults to 90 days, capped at 365. The role cannot be an admin role.</p>
          {formError !== null && <div className="service-accounts__error" role="alert">{formError}</div>}
          <div className="service-accounts__footer">
            <Button type="button" variant="primary" isLoading={creating} onClick={() => { void handleCreate(); }}>
              Create
            </Button>
            <Button type="button" variant="inverse" disabled={creating} onClick={() => { setShowCreate(false); setFormError(null); }}>
              Cancel
            </Button>
          </div>
        </Card>
      )}

      {actionError !== null && <div className="service-accounts__error" role="alert">{actionError}</div>}

      <Card padding="large">
        {error !== null && <div className="service-accounts__status service-accounts__status--error">Error: {error}</div>}
        {error === null && accounts === null && <div className="service-accounts__status">Loading...</div>}
        {error === null && accounts !== null && accounts.length === 0 && (
          <div className="service-accounts__status">No service accounts yet.</div>
        )}
        {error === null && accounts !== null && accounts.length > 0 && (
          <table className="service-accounts__table">
            <thead>
              <tr>
                <th>Name</th><th>Role</th><th>Status</th><th>Created</th><th>Last used</th><th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {accounts.map((sa) => (
                <tr key={sa.id}>
                  <td>
                    <div className="service-accounts__name">{sa.name}</div>
                    <div className="service-accounts__mono service-accounts__client-id">{sa.client_id}</div>
                  </td>
                  <td><Badge variant={roleVariant(sa.role)}>{roleLabel(sa.role)}</Badge></td>
                  <td><Badge variant={statusVariant(sa.status)}>{sa.status}</Badge></td>
                  <td>{formatDate(sa.created_at)}</td>
                  <td>{formatDate(sa.last_used_at)}</td>
                  <td className="service-accounts__row-actions">
                    {sa.status !== "revoked" && confirmRevokeID !== sa.id && (
                      <>
                        <Button
                          type="button" variant="inverse" size="small"
                          isLoading={busyID === sa.id}
                          onClick={() => { void handleRotate(sa); }}
                        >
                          Rotate
                        </Button>
                        <Button
                          type="button" variant="alert" size="small"
                          disabled={busyID === sa.id}
                          onClick={() => { setConfirmRevokeID(sa.id); setActionError(null); }}
                        >
                          Revoke
                        </Button>
                      </>
                    )}
                    {confirmRevokeID === sa.id && (
                      <>
                        <span className="service-accounts__confirm">Revoke {sa.name}?</span>
                        <Button
                          type="button" variant="alert" size="small"
                          isLoading={busyID === sa.id}
                          onClick={() => { void handleRevoke(sa); }}
                        >
                          Confirm
                        </Button>
                        <Button type="button" variant="inverse" size="small" onClick={() => { setConfirmRevokeID(null); }}>
                          Cancel
                        </Button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
