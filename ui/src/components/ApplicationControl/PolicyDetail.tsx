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

// ActiveModal is the union that captures which per-row modal is currently open. Encoding mutual exclusion in the type closes
// the Copilot finding on PR #189 — the previous shape kept two independent `useState` slots and relied on call-site discipline
// to avoid opening two modals at once. Now `add`, `edit`, `confirm-delete`, and `confirm-toggle` are exclusive by construction
// and a future helper that forgets to clear the previous state is a type error rather than a UX bug.
type ActiveModal =
  | { kind: "none" }
  | { kind: "add" }
  | { kind: "edit"; rule: ApplicationControlRule }
  | { kind: "confirm-delete"; rule: ApplicationControlRule }
  | { kind: "confirm-toggle"; rule: ApplicationControlRule };

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
  // activeModal is the union of every possible per-row modal state. Mutually exclusive by construction; opening a new modal
  // implicitly closes whichever was previously active because there's exactly one state slot.
  const [activeModal, setActiveModal] = useState<ActiveModal>({ kind: "none" });
  const closeModal = useCallback(() => { setActiveModal({ kind: "none" }); }, []);

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
      onClick={() => { setActiveModal({ kind: "add" }); }}
      disabled={!policy}
    >
      Add rule
    </Button>
  );

  const rules = policy?.rules ?? [];

  // confirmRule extracts the rule from a confirm-* modal kind so the JSX below stays terse; returns null for non-confirm
  // modals (the ConfirmActionModal won't render its content in that case).
  const confirmKind = activeModal.kind === "confirm-delete" || activeModal.kind === "confirm-toggle"
    ? activeModal.kind
    : null;
  const confirmRule = activeModal.kind === "confirm-delete" || activeModal.kind === "confirm-toggle"
    ? activeModal.rule
    : null;

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
              onEdit={(rule) => { setActiveModal({ kind: "edit", rule }); }}
              onToggle={(rule) => { setActiveModal({ kind: "confirm-toggle", rule }); }}
              onDelete={(rule) => { setActiveModal({ kind: "confirm-delete", rule }); }}
            />
          )}
        </>
      )}
      {policy && (
        <AddRuleModal
          open={activeModal.kind === "add"}
          policyID={policy.id}
          onClose={closeModal}
          onCreated={() => {
            closeModal();
            refresh();
          }}
        />
      )}
      {/*
        key={editKey}: forces React to remount EditRuleModal when the target rule changes (Gemini finding on PR #189).
        Without it, the autoFocus on the severity Select would only fire on the very first open of this component instance.
        Keyed by rule id so re-opening on the same row replays initialState; switching rows replays with the new row.
      */}
      <EditRuleModal
        key={activeModal.kind === "edit" ? `edit-${String(activeModal.rule.id)}` : "edit-closed"}
        open={activeModal.kind === "edit"}
        rule={activeModal.kind === "edit" ? activeModal.rule : null}
        onClose={closeModal}
        onSaved={() => {
          closeModal();
          refresh();
        }}
      />
      <ConfirmActionModal
        key={confirmRule ? `confirm-${String(confirmKind)}-${String(confirmRule.id)}` : "confirm-closed"}
        open={confirmRule !== null}
        title={confirmTitleFor(activeModal)}
        description={confirmDescriptionFor(activeModal)}
        confirmLabel={confirmLabelFor(activeModal)}
        confirmVariant={activeModal.kind === "confirm-delete" ? "alert" : "primary"}
        reasonPlaceholder={confirmReasonPlaceholderFor(activeModal)}
        onClose={closeModal}
        onConfirm={async (reason) => {
          if (!confirmRule) return;
          if (activeModal.kind === "confirm-delete") {
            await deleteAppControlRule(confirmRule.id, { reason });
          } else if (activeModal.kind === "confirm-toggle") {
            await updateAppControlRule(confirmRule.id, {
              enabled: !confirmRule.enabled,
              reason,
            });
          }
          closeModal();
          refresh();
        }}
      />
    </>
  );
}

// confirmTitleFor + the three sibling helpers shape the per-action copy passed into the shared ConfirmActionModal. Keeping the
// switch outside the component body so the modal can stay generic and the per-action vocabulary lives next to the dispatch.
function confirmTitleFor(active: ActiveModal): string {
  if (active.kind === "confirm-delete") return "Delete rule";
  if (active.kind === "confirm-toggle") return active.rule.enabled ? "Disable rule" : "Enable rule";
  return "";
}

function confirmDescriptionFor(active: ActiveModal): React.ReactNode {
  if (active.kind !== "confirm-delete" && active.kind !== "confirm-toggle") return "";
  const ident = active.rule.identifier;
  if (active.kind === "confirm-delete") {
    return (
      <>
        The rule for <code>{ident}</code> will be removed and the policy version
        will bump so every agent drops it on the next snapshot.
      </>
    );
  }
  if (active.rule.enabled) {
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

function confirmLabelFor(active: ActiveModal): string {
  if (active.kind === "confirm-delete") return "Delete rule";
  if (active.kind === "confirm-toggle") return active.rule.enabled ? "Disable rule" : "Enable rule";
  return "Confirm";
}

function confirmReasonPlaceholderFor(active: ActiveModal): string {
  if (active.kind === "confirm-delete") return "Why are you deleting this rule?";
  if (active.kind === "confirm-toggle") {
    return active.rule.enabled
      ? "Why are you disabling this rule?"
      : "Why are you re-enabling this rule?";
  }
  return "";
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
