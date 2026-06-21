import { useEffect, useState } from "react";
import { listUsers, setUserRole, setUserStatus, type AdminUser } from "../../api";
import { useCan, PermissionAction } from "../../permissions-core";
import { PageHeader } from "../ui/PageHeader";
import { Card } from "../ui/Card";
import { Button } from "../ui/Button";
import { Select } from "../ui/Input";
import { Badge, type BadgeVariant } from "../ui/Badge";
import "./Users.scss";

// ROLES are the seeded roles an admin may assign. super_admin is intentionally absent: the UI never grants it (only a super_admin may,
// via break-glass / SQL), and rows that already hold it render read-only. Mirrors the service-account bindable set.
const ROLES = [
  { value: "analyst", label: "Analyst" },
  { value: "senior_analyst", label: "Senior analyst" },
  { value: "auditor", label: "Auditor" },
  { value: "admin", label: "Admin" },
] as const;

const ROLE_LABELS = new Map<string, string>([
  ["analyst", "Analyst"],
  ["senior_analyst", "Senior analyst"],
  ["auditor", "Auditor"],
  ["admin", "Admin"],
  ["super_admin", "Super admin"],
  ["", "No role"],
]);

function roleLabel(role: string): string {
  return ROLE_LABELS.get(role) ?? role;
}

function roleVariant(role: string): BadgeVariant {
  switch (role) {
    case "super_admin":
    case "admin":
      return "info";
    default:
      return "neutral";
  }
}

// friendlyError maps the handler's status codes to operator-readable copy. fetchJSON throws "API error: <status> ..." without the
// reason body, so we key off the status: 403 is the super-admin restriction, 409 is a guardrail (last admin / self / break-glass).
function friendlyError(err: unknown, fallback: string): string {
  const msg = err instanceof Error ? err.message : "";
  if (msg.includes("403")) return "You do not have permission for that change (super-admin users can only be managed by a super admin).";
  if (msg.includes("409")) return "That change is not allowed: it would remove the last admin or affect your own or a break-glass account.";
  return err instanceof Error ? err.message : fallback;
}

export function Users() {
  const can = useCan();
  const canManage = can(PermissionAction.UserManage);

  const [users, setUsers] = useState<AdminUser[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busyID, setBusyID] = useState<number | null>(null);

  function reload(): void {
    listUsers()
      // Clear any prior load error on success so the page recovers after a transient failure (the render gates on error === null).
      .then((rows) => { setUsers(rows); setError(null); })
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : "Failed to load users";
        // Only blow away the table for an INITIAL load failure. A failed background refresh (post-mutation) keeps the existing
        // table and surfaces the problem as a transient action error instead.
        setUsers((current) => {
          if (current === null) { setError(msg); } else { setActionError(msg); }
          return current;
        });
      });
  }

  useEffect(() => {
    let cancelled = false;
    listUsers()
      .then((rows) => { if (!cancelled) { setUsers(rows); setError(null); } })
      .catch((err: unknown) => { if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load users"); });
    return () => { cancelled = true; };
  }, []);

  async function handleRole(u: AdminUser, role: string): Promise<void> {
    if (role === u.role) return;
    setBusyID(u.id);
    setActionError(null);
    // Optimistically reflect the new role so the controlled <select> does not snap back to the old value while the request is in
    // flight; reload() reconciles with server truth on success, and reverts the optimistic change on failure.
    setUsers((rows) => rows?.map((x) => (x.id === u.id ? { ...x, role, roles: [role] } : x)) ?? rows);
    try {
      await setUserRole(u.id, role);
      reload();
    } catch (err: unknown) {
      setActionError(friendlyError(err, "Failed to change role."));
      reload();
    } finally {
      setBusyID(null);
    }
  }

  async function handleStatus(u: AdminUser, status: "active" | "disabled"): Promise<void> {
    setBusyID(u.id);
    setActionError(null);
    try {
      await setUserStatus(u.id, status);
      reload();
    } catch (err: unknown) {
      setActionError(friendlyError(err, "Failed to change status."));
    } finally {
      setBusyID(null);
    }
  }

  return (
    <div className="users">
      <PageHeader
        title="Users"
        subtitle="Operators who can sign in to the console. Assign each a role and enable or disable access. New users arrive through single sign-on or break-glass."
      />

      {actionError !== null && <div className="users__error" role="alert">{actionError}</div>}

      <Card padding="large">
        {error !== null && <div className="users__status users__status--error">Error: {error}</div>}
        {error === null && users === null && <div className="users__status">Loading...</div>}
        {error === null && users !== null && users.length === 0 && <div className="users__status">No users yet.</div>}
        {error === null && users !== null && users.length > 0 && (
          <table className="users__table">
            <thead>
              <tr>
                <th>User</th><th>Role</th><th>Status</th><th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {users.map((u) => {
                // A row is editable only when the operator can manage users AND the target is neither a break-glass account nor a
                // super_admin (both of which the server refuses to modify through this surface). Read-only rows show badges, no controls.
                const editable = canManage && !u.is_breakglass && u.role !== "super_admin";
                const disabled = u.status === "disabled";
                return (
                  <tr key={u.id}>
                    <td>
                      <div className="users__name">
                        {u.display_name !== undefined && u.display_name !== "" ? u.display_name : u.email}
                      </div>
                      {u.display_name !== undefined && u.display_name !== "" && <div className="users__email">{u.email}</div>}
                      {u.is_breakglass && <Badge variant="medium">Break-glass</Badge>}
                    </td>
                    <td>
                      {editable ? (
                        <Select
                          id={`role-${String(u.id)}`}
                          aria-label={`Role for ${u.email}`}
                          inline={false}
                          value={u.role}
                          disabled={busyID === u.id}
                          onChange={(e) => { void handleRole(u, e.target.value); }}
                        >
                          {!ROLES.some((r) => r.value === u.role) && <option value={u.role}>{roleLabel(u.role)}</option>}
                          {ROLES.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
                        </Select>
                      ) : (
                        <Badge variant={roleVariant(u.role)}>{roleLabel(u.role)}</Badge>
                      )}
                    </td>
                    <td><Badge variant={disabled ? "neutral" : "success"}>{disabled ? "Disabled" : "Active"}</Badge></td>
                    <td className="users__row-actions">
                      {editable && (
                        <Button
                          type="button"
                          variant={disabled ? "inverse" : "alert"}
                          size="small"
                          isLoading={busyID === u.id}
                          onClick={() => { void handleStatus(u, disabled ? "active" : "disabled"); }}
                        >
                          {disabled ? "Enable" : "Disable"}
                        </Button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
