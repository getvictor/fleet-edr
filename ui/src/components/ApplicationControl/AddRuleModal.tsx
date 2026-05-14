import { useCallback, useEffect, useRef, useState } from "react";
import {
  createAppControlRule,
  AppControlApiError,
  ReauthRequiredError,
  type CreateAppControlRuleRequest,
} from "../../api";
import { useReauthRetry } from "../../hooks/useReauthRetry";
import { Button } from "../ui/Button";
import { Input, Select } from "../ui/Input";
import "./ApplicationControl.scss";

// AddRuleModalProps is the parent contract. open drives showModal() /
// close(); onClose fires on Cancel/Escape; onCreated fires after a
// successful POST so the parent can re-fetch the policy.
interface AddRuleModalProps {
  readonly open: boolean;
  readonly policyID: number;
  readonly onClose: () => void;
  readonly onCreated: () => void;
}

const DIALOG_TITLE_ID = "add-rule-modal-title";

// RULE_TYPES enumerates the values the schema's rule_type ENUM
// accepts. Only BINARY is enforced in the demo cut; the others
// render in the type selector with the disabled flag set so the
// camera-facing UI shows the post-demo roadmap without faking it.
const RULE_TYPES: { value: string; label: string; available: boolean }[] = [
  { value: "BINARY", label: "BINARY (file SHA-256)", available: true },
  { value: "CDHASH", label: "CDHASH (code-directory hash)", available: false },
  { value: "SIGNINGID", label: "SIGNINGID (Team:bundle.id)", available: false },
  { value: "CERTIFICATE", label: "CERTIFICATE (leaf SHA-256)", available: false },
  { value: "TEAMID", label: "TEAMID (Apple Developer team)", available: false },
  { value: "PATH", label: "PATH (canonical absolute)", available: false },
];

const SEVERITIES = ["low", "medium", "high", "critical"];
const BINARY_HEX_LENGTH = 64;
const BINARY_HEX_REGEX = /^[a-f0-9]{64}$/;

// validateBinaryIdentifier mirrors the server's BINARY validator
// (server/rules/internal/appcontrol/validate.go). Catching the
// format error client-side gives the operator immediate feedback
// instead of a round trip + a typed 400.
function validateBinaryIdentifier(value: string): string | null {
  const trimmed = value.trim().toLowerCase();
  if (trimmed.length === 0) return "Identifier is required.";
  if (trimmed.length !== BINARY_HEX_LENGTH) {
    return `BINARY identifier must be ${String(BINARY_HEX_LENGTH)} lowercase hex characters (was ${String(trimmed.length)}).`;
  }
  if (!BINARY_HEX_REGEX.test(trimmed)) {
    return "BINARY identifier must contain only lowercase hex (0-9 a-f).";
  }
  return null;
}

// errorMessageForCode maps the server's typed application_control.*
// error codes onto operator-readable copy. Anything unrecognised
// falls back to the raw message the server returned (already
// human-readable) so we don't black-hole unexpected failures.
const errorMessageByCode = new Map<string, string>([
  ["application_control.invalid_rule", "The rule didn't pass server-side validation."],
  ["application_control.duplicate_rule", "A rule with this identifier already exists in this policy."],
  ["application_control.policy_not_found", "The policy was deleted before the rule could be saved."],
  ["application_control.invalid_policy_id", "Invalid policy id."],
  ["application_control.invalid_json", "The request body was not valid JSON."],
]);

export function AddRuleModal({ open, policyID, onClose, onCreated }: AddRuleModalProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const [ruleType, setRuleType] = useState("BINARY");
  const [identifier, setIdentifier] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [customMsg, setCustomMsg] = useState("");
  const [customURL, setCustomURL] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Reset the form whenever the dialog opens. Otherwise a Cancel +
  // re-open would surface the previous attempt's values, which is
  // confusing for the demo recording (and for real operators).
  useEffect(() => {
    if (!open) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect -- intentional reset tied to the open prop transition
    setRuleType("BINARY");
    setIdentifier("");
    setSeverity("medium");
    setCustomMsg("");
    setCustomURL("");
    setReason("");
    setBusy(false);
    setFormError(null);
  }, [open]);

  // Open / close the native <dialog>. showModal() is what gives us
  // backdrop, focus trap, and Escape-to-cancel for free; the
  // declarative `open` attribute would render non-modal.
  useEffect(() => {
    const dlg = dialogRef.current;
    if (!dlg) return;
    if (open && !dlg.open) {
      dlg.showModal();
    } else if (!open && dlg.open) {
      dlg.close();
    }
  }, [open]);

  // Escape and backdrop click both route through onClose so the
  // parent's open-state is the single source of truth.
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

  const submitCreate = useCallback(
    (req: CreateAppControlRuleRequest) => createAppControlRule(policyID, req),
    [policyID],
  );
  const { call: callCreate, modal: reauthModal } = useReauthRetry(submitCreate);

  const submitDisabled = busy || reason.trim().length === 0 || identifier.trim().length === 0;

  async function handleSubmit(e: React.SyntheticEvent) {
    e.preventDefault();
    if (submitDisabled) return;
    if (ruleType === "BINARY") {
      const validation = validateBinaryIdentifier(identifier);
      if (validation) {
        setFormError(validation);
        return;
      }
    }
    setFormError(null);
    setBusy(true);
    try {
      const req: CreateAppControlRuleRequest = {
        rule_type: ruleType,
        identifier: identifier.trim().toLowerCase(),
        severity,
        reason: reason.trim(),
      };
      if (customMsg.trim().length > 0) req.custom_msg = customMsg.trim();
      if (customURL.trim().length > 0) req.custom_url = customURL.trim();
      await callCreate(req);
      onCreated();
    } catch (err) {
      if (err instanceof ReauthRequiredError) {
        // useReauthRetry's modal is mounted at the bottom of this
        // component; the user finishes the reauth and the original
        // call retries on its own. No UI work to do here.
        return;
      }
      if (err instanceof AppControlApiError) {
        setFormError(errorMessageByCode.get(err.code) ?? err.message);
      } else if (err instanceof Error) {
        setFormError(err.message);
      } else {
        setFormError("Failed to create rule.");
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
          <h2 id={DIALOG_TITLE_ID} className="app-control-dialog__title">Add rule</h2>
          <p className="app-control-dialog__subtitle">
            Block an executable on every assigned host. The rule fans
            out to enrolled agents on save.
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
          <Select
            id="rule-type"
            label="Type"
            value={ruleType}
            onChange={(e) => { setRuleType(e.target.value); }}
            disabled={busy}
          >
            {RULE_TYPES.map((t) => (
              <option
                key={t.value}
                value={t.value}
                disabled={!t.available}
              >
                {t.label}{t.available ? "" : " (coming soon)"}
              </option>
            ))}
          </Select>

          <Input
            id="rule-identifier"
            label="Identifier"
            type="text"
            autoComplete="off"
            spellCheck={false}
            placeholder={ruleType === "BINARY" ? "64 lowercase hex characters (sha256)" : ""}
            value={identifier}
            onChange={(e) => { setIdentifier(e.target.value); }}
            disabled={busy}
            autoFocus
          />

          <Select
            id="rule-severity"
            label="Severity"
            value={severity}
            onChange={(e) => { setSeverity(e.target.value); }}
            disabled={busy}
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </Select>

          <Input
            id="rule-custom-msg"
            label="Custom message (optional)"
            type="text"
            placeholder="Blocked by corporate policy"
            value={customMsg}
            onChange={(e) => { setCustomMsg(e.target.value); }}
            disabled={busy}
          />

          <Input
            id="rule-custom-url"
            label="More info URL (optional, https only)"
            type="url"
            placeholder="https://help.example.com/blocked"
            value={customURL}
            onChange={(e) => { setCustomURL(e.target.value); }}
            disabled={busy}
          />

          <Input
            id="rule-reason"
            label="Reason (required for audit log)"
            type="text"
            placeholder="Why are you authoring this rule?"
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
              {busy ? "Saving…" : "Save rule"}
            </Button>
          </div>
        </form>
      </dialog>
      {reauthModal}
    </>
  );
}
