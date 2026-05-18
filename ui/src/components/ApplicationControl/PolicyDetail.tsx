import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  getAppControlPolicy,
  deleteAppControlRule,
  updateAppControlRule,
} from "../../api";
import type { ApplicationControlPolicy, ApplicationControlRule } from "../../types";
import { PageHeader } from "../ui/PageHeader";
import { Table, EmptyState } from "../ui/Table";
import { Button } from "../ui/Button";
import { Badge, type BadgeVariant } from "../ui/Badge";
import { AddRuleModal } from "./AddRuleModal";
import { EditRuleModal } from "./EditRuleModal";
import { ConfirmActionModal } from "./ConfirmActionModal";
import "./ApplicationControl.scss";

// pendingConfirm captures which per-row action the operator clicked + the row it targets, so the shared ConfirmActionModal can
// render the right copy and dispatch the right API call when the operator submits a reason. The kind discriminator drives both
// the modal labels AND the onConfirm side-effect.
type PendingConfirm =
  | { kind: "delete"; rule: ApplicationControlRule }
  | { kind: "toggle"; rule: ApplicationControlRule };

const SEVERITY_VARIANTS: Record<string, BadgeVariant> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
};

// truncateIdentifier renders the leading 16 chars of a SHA-256
// identifier so the rules table stays scannable without dropping the
// disambiguating prefix. Full value is in the row's title attribute
// for inspection. Identifiers shorter than the cap render verbatim
// — TEAMID / SIGNINGID rules (post-demo) would otherwise come back
// cropped.
const IDENTIFIER_DISPLAY_CHARS = 16;
function truncateIdentifier(value: string): string {
  if (value.length <= IDENTIFIER_DISPLAY_CHARS) return value;
  return value.slice(0, IDENTIFIER_DISPLAY_CHARS) + "…";
}

// PolicyDetail is the policy-rules surface the demo's Add Rule modal
// hangs off. Demo beat #2 (admin pastes a SHA-256, hits Save, sees
// the row appear) is its primary job; the per-row edit / disable /
// delete buttons render disabled with the "coming soon" tooltip
// pattern PoliciesList uses on its New Policy button. The Show
// History toggle is the audit-history scaffolding for post-demo
// work.
export function PolicyDetail() {
  const { id: idParam } = useParams<{ id: string }>();
  const policyID = idParam ? Number.parseInt(idParam, 10) : Number.NaN;
  const [policy, setPolicy] = useState<ApplicationControlPolicy | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  // editingRule + pendingConfirm own the per-row modal state. Only one of the two is ever populated at a time; the modals close
  // when their target is set to null. Defined here so the rules table inside RulesTable can fire the open callbacks via props.
  const [editingRule, setEditingRule] = useState<ApplicationControlRule | null>(null);
  const [pendingConfirm, setPendingConfirm] = useState<PendingConfirm | null>(null);

  // refreshKey bumps to force a re-fetch (e.g. after Save in the
  // modal). useEffect below owns the actual fetch lifecycle so the
  // setState calls happen in async callbacks rather than synchronously
  // inside an effect body (react-hooks/set-state-in-effect).
  const [refreshKey, setRefreshKey] = useState(0);
  const refresh = useCallback(() => {
    setRefreshKey((k) => k + 1);
  }, []);

  useEffect(() => {
    if (!Number.isFinite(policyID)) return;
    let cancelled = false;
    setLoading(true); // eslint-disable-line react-hooks/set-state-in-effect -- data fetch pattern
    setError(null);
    getAppControlPolicy(policyID)
      .then((result) => {
        if (!cancelled) setPolicy(result);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Unknown error");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, [policyID, refreshKey]);

  if (!Number.isFinite(policyID)) {
    return (
      <>
        <PageHeader
          title="Application control"
          subtitle={
            <Link className="link-button" to="/app-control">
              ← Back to policies
            </Link>
          }
        />
        <EmptyState>Invalid policy id in URL.</EmptyState>
      </>
    );
  }

  const title = policy?.name ?? "Application control";
  const subtitle = (
    <>
      <Link className="link-button" to="/app-control">
        ← Back to policies
      </Link>
      {policy && (
        <>
          {" "}<span className="app-control__divider">·</span>{" "}
          version {policy.version}
          {" "}<span className="app-control__divider">·</span>{" "}
          assignments: <span className="app-control__assignment">all hosts</span>
        </>
      )}
    </>
  );

  const actions = (
    <Button
      variant="primary"
      onClick={() => { setAddOpen(true); }}
      disabled={!policy}
    >
      Add rule
    </Button>
  );

  const rules = policy?.rules ?? [];

  return (
    <>
      <PageHeader title={title} subtitle={subtitle} actions={actions} />
      {loading && <EmptyState>Loading policy...</EmptyState>}
      {error && !loading && <EmptyState>Error: {error}</EmptyState>}
      {!loading && !error && policy && (
        <>
          {policy.description && (
            <p className="app-control__description">{policy.description}</p>
          )}
          {rules.length === 0 ? (
            <EmptyState>
              This policy has no rules yet. Click <strong>Add rule</strong> to
              author the first one.
            </EmptyState>
          ) : (
            <RulesTable
              rules={rules}
              onEdit={(rule) => { setEditingRule(rule); }}
              onToggle={(rule) => { setPendingConfirm({ kind: "toggle", rule }); }}
              onDelete={(rule) => { setPendingConfirm({ kind: "delete", rule }); }}
            />
          )}
        </>
      )}
      {policy && (
        <AddRuleModal
          open={addOpen}
          policyID={policy.id}
          onClose={() => { setAddOpen(false); }}
          onCreated={() => {
            setAddOpen(false);
            refresh();
          }}
        />
      )}
      <EditRuleModal
        open={editingRule !== null}
        rule={editingRule}
        onClose={() => { setEditingRule(null); }}
        onSaved={() => {
          setEditingRule(null);
          refresh();
        }}
      />
      <ConfirmActionModal
        open={pendingConfirm !== null}
        title={confirmTitleFor(pendingConfirm)}
        description={confirmDescriptionFor(pendingConfirm)}
        confirmLabel={confirmLabelFor(pendingConfirm)}
        confirmVariant={pendingConfirm?.kind === "delete" ? "alert" : "primary"}
        reasonPlaceholder={confirmReasonPlaceholderFor(pendingConfirm)}
        onClose={() => { setPendingConfirm(null); }}
        onConfirm={async (reason) => {
          if (!pendingConfirm) return;
          if (pendingConfirm.kind === "delete") {
            await deleteAppControlRule(pendingConfirm.rule.id, { reason });
          } else {
            await updateAppControlRule(pendingConfirm.rule.id, {
              enabled: !pendingConfirm.rule.enabled,
              reason,
            });
          }
          setPendingConfirm(null);
          refresh();
        }}
      />
    </>
  );
}

// confirmTitleFor + the three sibling helpers shape the per-action copy passed into the shared ConfirmActionModal. Keeping the
// switch outside the component body so the modal can stay generic and the per-action vocabulary lives next to the dispatch.
function confirmTitleFor(pending: PendingConfirm | null): string {
  if (!pending) return "";
  if (pending.kind === "delete") return "Delete rule";
  return pending.rule.enabled ? "Disable rule" : "Enable rule";
}

function confirmDescriptionFor(pending: PendingConfirm | null): React.ReactNode {
  if (!pending) return "";
  const ident = pending.rule.identifier;
  if (pending.kind === "delete") {
    return (
      <>
        The rule for <code>{ident}</code> will be removed and the policy version
        will bump so every agent drops it on the next snapshot.
      </>
    );
  }
  if (pending.rule.enabled) {
    return (
      <>
        Disabling pauses enforcement for <code>{ident}</code>. The rule stays
        on the policy and the agents drop it on the next snapshot until you
        re-enable.
      </>
    );
  }
  return (
    <>
      Re-enabling resumes enforcement for <code>{ident}</code>. The agents
      pick it up on the next snapshot.
    </>
  );
}

function confirmLabelFor(pending: PendingConfirm | null): string {
  if (!pending) return "Confirm";
  if (pending.kind === "delete") return "Delete rule";
  return pending.rule.enabled ? "Disable rule" : "Enable rule";
}

function confirmReasonPlaceholderFor(pending: PendingConfirm | null): string {
  if (!pending) return "";
  if (pending.kind === "delete") return "Why are you deleting this rule?";
  return pending.rule.enabled
    ? "Why are you disabling this rule?"
    : "Why are you re-enabling this rule?";
}

interface RulesTableProps {
  readonly rules: ApplicationControlRule[];
  readonly onEdit: (rule: ApplicationControlRule) => void;
  readonly onToggle: (rule: ApplicationControlRule) => void;
  readonly onDelete: (rule: ApplicationControlRule) => void;
}

function RulesTable({ rules, onEdit, onToggle, onDelete }: RulesTableProps) {
  return (
    <Table>
      <thead>
        <tr>
          <th>Type</th>
          <th>Identifier</th>
          <th>Severity</th>
          <th>Custom message</th>
          <th>Last modified</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {rules.map((rule) => (
          <tr key={rule.id}>
            <td>
              <Badge variant="neutral">{rule.rule_type}</Badge>
            </td>
            <td title={rule.identifier} className="app-control__identifier">
              {truncateIdentifier(rule.identifier)}
            </td>
            <td>
              <Badge variant={SEVERITY_VARIANTS[rule.severity] ?? "neutral"}>
                {rule.severity}
              </Badge>
            </td>
            <td>{rule.custom_msg ?? <span className="app-control__muted">—</span>}</td>
            <td>{new Date(rule.updated_at).toLocaleString()}</td>
            <td className="app-control__row-actions">
              {/* Edit / Disable / Delete each open a modal that prompts for an audit reason before firing the PATCH / DELETE
                  endpoint server-side. The handlers live on PolicyDetail so refresh-on-success is wired in one place. */}
              <Button
                variant="text-link"
                size="small"
                onClick={() => { onEdit(rule); }}
              >
                Edit
              </Button>
              <Button
                variant="text-link"
                size="small"
                onClick={() => { onToggle(rule); }}
                title={rule.enabled ? "Pause enforcement for this rule" : "Resume enforcement for this rule"}
              >
                {rule.enabled ? "Disable" : "Enable"}
              </Button>
              <Button
                variant="text-link"
                size="small"
                onClick={() => { onDelete(rule); }}
              >
                Delete
              </Button>
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
