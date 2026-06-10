import { useEffect, useMemo, useState } from "react";
import {
  updateAppControlRule,
  type UpdateAppControlRuleRequest,
} from "../../api";
import { useReauthRetry } from "../../hooks/useReauthRetry";
import { ReauthModal } from "../ReauthModal";
import type { ApplicationControlRule } from "../../types";
import { Input, Select } from "../ui/Input";
import { AppControlDialogShell } from "./AppControlDialogShell";
import { applyAppControlSubmitError } from "./dialogErrors";
import "./ApplicationControl.scss";

interface EditRuleModalProps {
  readonly open: boolean;
  // rule is the row being edited. The modal pre-fills its inputs from this on open; the parent passes the current row so the
  // operator doesn't see stale data after a sibling action refreshed the list.
  readonly rule: ApplicationControlRule | null;
  readonly onClose: () => void;
  readonly onSaved: () => void;
}

const DIALOG_TITLE_ID = "edit-rule-modal-title";
const SEVERITIES = ["low", "medium", "high", "critical"];

// errorMessageByCode mirrors AddRuleModal: known typed error codes map to UI-readable messages; anything else falls through to
// the server's free-form `message` which the handler already writes as operator-readable.
const errorMessageByCode = new Map<string, string>([
  ["application_control.rule_not_found", "The rule was deleted before the change could be saved."],
  ["application_control.invalid_rule", "The change didn't pass server-side validation."],
  ["application_control.invalid_json", "The request body was not valid JSON."],
]);

export function EditRuleModal({ open, rule, onClose, onSaved }: EditRuleModalProps) {
  // initialState mirrors the rule's mutable fields at the moment the modal opened. The submit handler diffs current state
  // against this baseline so the PATCH body only carries fields that actually changed, which keeps the audit log honest
  // (a 1-field-changed PATCH audits as a 1-field change, not a 5-field rewrite).
  const initialState = useMemo(() => ({
    severity: rule?.severity ?? "medium",
    customMsg: rule?.custom_msg ?? "",
    customURL: rule?.custom_url ?? "",
    comment: rule?.comment ?? "",
  }), [rule]);

  const [severity, setSeverity] = useState(initialState.severity);
  const [customMsg, setCustomMsg] = useState(initialState.customMsg);
  const [customURL, setCustomURL] = useState(initialState.customURL);
  const [comment, setComment] = useState(initialState.comment);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Reset on every open so a Cancel + re-open doesn't surface the previous attempt's edits. The parent also keys this component
  // on the target rule id (PolicyDetail.tsx) so this effect's reset is a defense-in-depth path.
  useEffect(() => {
    if (!open) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect -- intentional reset tied to the open prop transition
    setSeverity(initialState.severity);
    setCustomMsg(initialState.customMsg);
    setCustomURL(initialState.customURL);
    setComment(initialState.comment);
    setReason("");
    setBusy(false);
    setFormError(null);
  }, [open, initialState]);

  const { call: callUpdate, modal: reauthModal } = useReauthRetry(
    (ruleID: number, req: UpdateAppControlRuleRequest) => updateAppControlRule(ruleID, req),
  );

  // diff captures only the fields the operator actually changed. Sending the unchanged baseline would still bump the policy
  // version on the server (because UpdateRule treats any field as a mutation), inflating the audit row + the snapshot fan-out
  // for no observable change. Comparing against initialState keeps the wire body honest.
  const diff = useMemo<Partial<UpdateAppControlRuleRequest>>(() => {
    const d: Partial<UpdateAppControlRuleRequest> = {};
    if (severity !== initialState.severity) d.severity = severity;
    if (customMsg.trim() !== initialState.customMsg) d.custom_msg = customMsg.trim();
    if (customURL.trim() !== initialState.customURL) d.custom_url = customURL.trim();
    if (comment.trim() !== initialState.comment) d.comment = comment.trim();
    return d;
  }, [severity, customMsg, customURL, comment, initialState]);

  const hasChanges = Object.keys(diff).length > 0;
  const submitDisabled = busy || reason.trim().length === 0 || !hasChanges;

  async function handleSubmit(e: React.SyntheticEvent) {
    e.preventDefault();
    if (!rule) return;
    if (submitDisabled) return;
    // Mirror AddRuleModal's URL guard so an http/https check fires client-side; BlockAlert.swift rejects other schemes
    // server-side but a round-trip is wasteful.
    if (customURL.trim().length > 0) {
      try {
        const parsed = new URL(customURL.trim());
        if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
          setFormError("More info URL must use http or https.");
          return;
        }
      } catch {
        setFormError("More info URL is not a valid URL.");
        return;
      }
    }
    setFormError(null);
    setBusy(true);
    try {
      await callUpdate(rule.id, { ...diff, reason: reason.trim() });
      onSaved();
    } catch (err) {
      if (applyAppControlSubmitError(err, setFormError, errorMessageByCode, "Failed to update rule.")) {
        return;
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <AppControlDialogShell
      open={open}
      onClose={onClose}
      titleId={DIALOG_TITLE_ID}
      title="Edit rule"
      subtitle="Severity + custom message + URL + comment are editable. Rule type and identifier are fixed once the rule is created."
      formError={formError}
      busy={busy}
      submitDisabled={submitDisabled}
      submitLabel="Save changes"
      onSubmit={(e) => { void handleSubmit(e); }}
      reauthModal={<ReauthModal {...reauthModal} />}
    >
      {rule && (
        <p className="app-control-dialog__readonly">
          <strong>{rule.rule_type}</strong> · <code>{rule.identifier}</code>
        </p>
      )}

      <Select
        id="edit-rule-severity"
        label="Severity"
        inline={false}
        value={severity}
        onChange={(e) => { setSeverity(e.target.value); }}
        disabled={busy}
        autoFocus
      >
        {SEVERITIES.map((s) => (
          <option key={s} value={s}>{s}</option>
        ))}
      </Select>

      <Input
        id="edit-rule-custom-msg"
        label="Custom message"
        type="text"
        placeholder="Blocked by corporate policy"
        value={customMsg}
        onChange={(e) => { setCustomMsg(e.target.value); }}
        disabled={busy}
      />

      <Input
        id="edit-rule-custom-url"
        label="More info URL (http/https only)"
        type="url"
        placeholder="https://help.example.com/blocked"
        value={customURL}
        onChange={(e) => { setCustomURL(e.target.value); }}
        disabled={busy}
      />

      <Input
        id="edit-rule-comment"
        label="Comment (internal)"
        type="text"
        placeholder="Optional note for other admins"
        value={comment}
        onChange={(e) => { setComment(e.target.value); }}
        disabled={busy}
      />

      <Input
        id="edit-rule-reason"
        label="Reason (required for audit log)"
        type="text"
        placeholder="Why are you editing this rule?"
        value={reason}
        onChange={(e) => { setReason(e.target.value); }}
        disabled={busy}
      />
    </AppControlDialogShell>
  );
}
