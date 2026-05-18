import { useEffect, useState } from "react";
import { useReauthRetry } from "../../hooks/useReauthRetry";
import { ReauthModal } from "../ReauthModal";
import { Input } from "../ui/Input";
import { AppControlDialogShell } from "./AppControlDialogShell";
import { applyAppControlSubmitError } from "./dialogErrors";
import "./ApplicationControl.scss";

// ConfirmActionModal asks the operator to type a reason before a destructive or visible action goes through. Used by the
// disable/enable toggle + delete button on the rules table — both endpoints require a reason on the wire for the audit row, so a
// confirmation dialog is the right UX rather than a one-click action. The shared shape keeps the dialog vocabulary uniform
// across actions; per-action labels + button copy are passed in.
interface ConfirmActionModalProps {
  readonly open: boolean;
  readonly title: string;
  readonly description: React.ReactNode;
  readonly confirmLabel: string;
  // confirmVariant controls the Save button's color — `alert` for delete (red), `primary` for non-destructive confirmations.
  readonly confirmVariant?: "primary" | "alert";
  readonly reasonPlaceholder?: string;
  readonly onClose: () => void;
  // onConfirm receives the trimmed reason and returns a promise; the modal stays open until the promise resolves so the operator
  // sees the "Saving…" state. Errors thrown from onConfirm surface inline as form errors (typed AppControlApiError codes are
  // mapped to human messages via errorMessageByCode); ReauthRequiredError is intercepted by useReauthRetry.
  readonly onConfirm: (reason: string) => Promise<void>;
}

const DIALOG_TITLE_ID = "confirm-action-modal-title";

// errorMessageByCode mirrors the AddRuleModal pattern: known typed error codes map to a UI-readable message; anything else falls
// through to the server's free-form `message` (already operator-readable).
const errorMessageByCode = new Map<string, string>([
  ["application_control.rule_not_found", "The rule was deleted before the change could be saved."],
  ["application_control.policy_not_found", "The policy was deleted before the change could be saved."],
  ["application_control.policy_immutable", "The seed Default policy cannot be deleted."],
  ["application_control.invalid_rule", "The change didn't pass server-side validation."],
  ["application_control.invalid_policy", "The change didn't pass server-side validation."],
  ["application_control.invalid_json", "The request body was not valid JSON."],
]);

export function ConfirmActionModal({
  open,
  title,
  description,
  confirmLabel,
  confirmVariant = "primary",
  reasonPlaceholder,
  onClose,
  onConfirm,
}: ConfirmActionModalProps) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Reset on every open so the previous attempt's reason doesn't leak across actions. The parent also re-mounts this component
  // via a key on each new pending action (PolicyDetail.tsx) so this effect's reset is a defense-in-depth path.
  useEffect(() => {
    if (!open) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect -- intentional reset tied to the open prop transition
    setReason("");
    setBusy(false);
    setFormError(null);
  }, [open]);

  const { call: callConfirm, modal: reauthModal } = useReauthRetry(onConfirm);

  const trimmedReason = reason.trim();
  const submitDisabled = busy || trimmedReason.length === 0;

  async function handleSubmit(e: React.SyntheticEvent) {
    e.preventDefault();
    if (submitDisabled) return;
    setFormError(null);
    setBusy(true);
    try {
      await callConfirm(trimmedReason);
      // Caller is responsible for closing the modal in response to onConfirm resolving;
      // staying open here lets a multi-step parent flow render an in-place success state if it wants.
    } catch (err) {
      if (applyAppControlSubmitError(err, setFormError, errorMessageByCode, "Action failed.")) {
        return; // ReauthRequiredError — useReauthRetry's modal handles the rest.
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
      title={title}
      subtitle={description}
      formError={formError}
      busy={busy}
      submitDisabled={submitDisabled}
      submitLabel={confirmLabel}
      submitVariant={confirmVariant}
      onSubmit={(e) => { void handleSubmit(e); }}
      reauthModal={<ReauthModal {...reauthModal} />}
    >
      <Input
        id="confirm-action-reason"
        label="Reason (required for audit log)"
        type="text"
        placeholder={reasonPlaceholder ?? "Why are you making this change?"}
        value={reason}
        onChange={(e) => { setReason(e.target.value); }}
        disabled={busy}
        autoFocus
      />
    </AppControlDialogShell>
  );
}
