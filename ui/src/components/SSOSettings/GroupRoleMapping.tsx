import { useState } from "react";
import type { SSOGroupRole } from "../../api";
import { BINDABLE_ROLES, roleLabel } from "../../roles";
import { Card } from "../ui/Card";
import { Button } from "../ui/Button";
import { Input, Select } from "../ui/Input";
import { Table, EmptyState } from "../ui/Table";

interface GroupRoleMappingProps {
  readonly claim: string;
  readonly groupRoles: readonly SSOGroupRole[];
  readonly requestGroupsScope: boolean;
  readonly onClaimChange: (claim: string) => void;
  readonly onGroupRolesChange: (groupRoles: SSOGroupRole[]) => void;
  readonly onRequestGroupsScopeChange: (request: boolean) => void;
}

// GroupRoleMapping edits which IdP groups grant which role at SSO sign-in: the ID-token claim that lists the groups, whether the groups
// scope is requested, and the group to role pairs. The parent owns the values and saves them with the rest of the configuration.
export function GroupRoleMapping({
  claim,
  groupRoles,
  requestGroupsScope,
  onClaimChange,
  onGroupRolesChange,
  onRequestGroupsScopeChange,
}: GroupRoleMappingProps) {
  const [newGroup, setNewGroup] = useState("");
  const [newRole, setNewRole] = useState<string>("analyst");

  const trimmed = newGroup.trim();
  const duplicate = groupRoles.some((gr) => gr.group === trimmed);
  const canAdd = trimmed !== "" && !duplicate;

  function add() {
    if (!canAdd) return;
    onGroupRolesChange([...groupRoles, { group: trimmed, role: newRole }]);
    setNewGroup("");
  }

  return (
    <Card padding="large">
      <div>
        <h2 className="sso-settings__card-title">Group to role mapping</h2>
        <p className="sso-settings__help">
          At each sign-in, an operator gets the most privileged role among their mapped groups, or the default role when none of their
          groups is mapped. A role set in the Users page is replaced at the next sign-in. A super admin keeps their role, and so does the
          last active admin.
        </p>
      </div>

      <div className="sso-settings__grid sso-settings__mapping">
        <div className="sso-settings__field-full">
          <Input
            id="sso-groups-claim"
            label="Groups claim"
            type="text"
            placeholder="groups"
            value={claim}
            onChange={(e) => {
              onClaimChange(e.target.value);
            }}
            aria-describedby="sso-groups-claim-help"
          />
          <p id="sso-groups-claim-help" className="sso-settings__help">
            The ID-token claim that lists the operator&apos;s groups. Leave it empty to turn mapping off.
          </p>
        </div>

        <div className="sso-settings__field-full">
          <label className="sso-settings__checkbox">
            <input
              type="checkbox"
              checked={requestGroupsScope}
              onChange={(e) => {
                onRequestGroupsScopeChange(e.target.checked);
              }}
            />{" "}
            Request the <code>groups</code> scope
          </label>
          <p className="sso-settings__help">Some providers, Okta among them, send the groups claim only when this scope is requested.</p>
        </div>
      </div>

      {groupRoles.length === 0 ? (
        <EmptyState>No group mappings.</EmptyState>
      ) : (
        <Table>
          <thead>
            <tr>
              <th>Group</th>
              <th>Role</th>
              <th aria-label="Actions" />
            </tr>
          </thead>
          <tbody>
            {groupRoles.map((gr) => (
              <tr key={gr.group}>
                <td>
                  <code>{gr.group}</code>
                </td>
                <td>{roleLabel(gr.role)}</td>
                <td>
                  <Button
                    type="button"
                    variant="text-link"
                    aria-label={`Remove ${gr.group}`}
                    onClick={() => {
                      onGroupRolesChange(groupRoles.filter((other) => other.group !== gr.group));
                    }}
                  >
                    Remove
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      <div className="sso-settings__mapping-add">
        <Input
          id="sso-new-group"
          label="Group"
          type="text"
          placeholder="edr-admins"
          value={newGroup}
          onChange={(e) => {
            setNewGroup(e.target.value);
          }}
          onKeyDown={(e) => {
            // Enter adds the mapping rather than submitting the whole settings form.
            if (e.key === "Enter") {
              e.preventDefault();
              add();
            }
          }}
        />
        <Select
          id="sso-new-group-role"
          label="Role"
          inline={false}
          value={newRole}
          onChange={(e) => {
            setNewRole(e.target.value);
          }}
        >
          {BINDABLE_ROLES.map((r) => (
            <option key={r.value} value={r.value}>
              {r.label}
            </option>
          ))}
        </Select>
        <Button type="button" variant="inverse" disabled={!canAdd} onClick={add}>
          Add mapping
        </Button>
      </div>
      {duplicate && <p className="sso-settings__help">{trimmed} is already mapped. Remove it first to change its role.</p>}
    </Card>
  );
}
