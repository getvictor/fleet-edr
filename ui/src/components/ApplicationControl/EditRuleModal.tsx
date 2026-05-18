import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  updateAppControlRule,
  AppControlApiError,
  ReauthRequiredError,
  type UpdateAppControlRuleRequest,
} from "../../api";
import { useReauthRetry } from "../../hooks/useReauthRetry";
import { ReauthModal } from "../ReauthModal";
import type { ApplicationControlRule } from "../../types";
import { Button } from "../ui/Button";
import { Input, Select } from "../ui/Input";
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
  const dialogRef = useRef<HTMLDialogElement>(null);
  // initialState mirrors the rule's mutable fields at the moment the modal opened. The submit handler diffs current state
  // against this baseline so the PATCH body only carries fields that actually changed — that keeps the audit log honest
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

  // Reset on every open so a Cancel + re-open doesn't surface the previous attempt's edits.
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

  useEffect(() => {
    const dlg = dialogRef.current;
    if (!dlg) return;
    if (open && !dlg.open) {
      dlg.showModal();
    } else if (!open && dlg.open) {
      dlg.close();
    }
  }, [open]);

  const handleCancel = useCallback((e: React.SyntheticEvent<HTMLDialogElement>) => {
    e.preventDefault();
    onClose();
  }, [onClose]);

  useEffect(() => {
    const dlg = dialogRef.current;
    if (!dlg) return undefined;
    const onBackdrop = (e: MouseEvent) => {
      if (e.target === dlg) onClose();
    };
    dlg.addEventListener("click", onBackdrop);
    return () => { dlg.removeEventListener("click", onBackdrop); };
  }, [onClose]);

  const submitUpdate = useCallback(
    (ruleID: number, req: UpdateAppControlRuleRequest) => updateAppControlRule(ruleID, req),
    [],
  );
  const { call: callUpdate, modal: reauthModal } = useReauthRetry(submitUpdate);

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
  // Submit is disabled when busy, when no reason has been typed yet, or when nothing actually changed. The rule-null case is
  // handled by the early return below — when the parent hasn't given us a rule the modal also wouldn't be `open`, so this
  // path is defensive rather than load-bearing.
  const submitDisabled = busy || reason.trim().length === 0 || !hasChanges;

  async function handleSubmit(e: React.SyntheticEvent) {
    e.preventDefault();
    if (!rule) return; // narrows rule to non-null for the rule.id access below.
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
      if (err instanceof ReauthRequiredError) {
        // useReauthRetry's modal is mounted at the bottom; the user finishes the reauth and the original call retries.
        return;
      }
      if (err instanceof AppControlApiError) {
        setFormError(errorMessageByCode.get(err.code) ?? err.message);
      } else if (err instanceof Error) {
        setFormError(err.message);
      } else {
        setFormError("Failed to update rule.");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <dialog
        ref={dialogRef}
        className="app-control-dialog"
        aria-labelledby={DIALOG_TITLE_ID}
        onCancel={handleCancel}
      >
        <div className="app-control-dialog__header">
          <h2 id={DIALOG_TITLE_ID} className="app-control-dialog__title">Edit rule</h2>
          <p className="app-control-dialog__subtitle">
            Severity + custom message + URL + comment are editable. Rule type and identifier are fixed
            once the rule is created.
          </p>
        </div>

        {formError && (
          <div className="app-control-dialog__error" role="alert">
            {formError}
          </div>
        )}

        <form
          onSubmit={(e) => { void handleSubmit(e); }}
          className="app-control-dialog__form"
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

          <div className="app-control-dialog__actions">
            <Button
              type="button"
              variant="text-link"
              onClick={onClose}
              disabled={busy}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={submitDisabled} isLoading={busy}>
              {busy ? "Saving…" : "Save changes"}
            </Button>
          </div>
        </form>
      </dialog>
      <ReauthModal {...reauthModal} />
    </>
  );
}
