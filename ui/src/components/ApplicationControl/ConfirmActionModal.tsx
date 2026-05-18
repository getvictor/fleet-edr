import { useCallback, useEffect, useRef, useState } from "react";
import { AppControlApiError, ReauthRequiredError } from "../../api";
import { useReauthRetry } from "../../hooks/useReauthRetry";
import { ReauthModal } from "../ReauthModal";
import { Button } from "../ui/Button";
import { Input } from "../ui/Input";
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
  const dialogRef = useRef<HTMLDialogElement>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Reset on every open so the previous attempt's reason doesn't leak across actions.
  useEffect(() => {
    if (!open) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect -- intentional reset tied to the open prop transition
    setReason("");
    setBusy(false);
    setFormError(null);
  }, [open]);

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

  const wrappedConfirm = useCallback(
    (trimmedReason: string) => onConfirm(trimmedReason),
    [onConfirm],
  );
  const { call: callConfirm, modal: reauthModal } = useReauthRetry(wrappedConfirm);

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
      if (err instanceof ReauthRequiredError) {
        // useReauthRetry's modal is mounted at the bottom of this component; the user finishes the reauth and the original call
        // retries on its own. No UI work to do here.
        return;
      }
      if (err instanceof AppControlApiError) {
        setFormError(errorMessageByCode.get(err.code) ?? err.message);
      } else if (err instanceof Error) {
        setFormError(err.message);
      } else {
        setFormError("Action failed.");
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
          <h2 id={DIALOG_TITLE_ID} className="app-control-dialog__title">{title}</h2>
          <p className="app-control-dialog__subtitle">{description}</p>
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

          <div className="app-control-dialog__actions">
            <Button
              type="button"
              variant="text-link"
              onClick={onClose}
              disabled={busy}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant={confirmVariant}
              disabled={submitDisabled}
              isLoading={busy}
            >
              {busy ? "Saving…" : confirmLabel}
            </Button>
          </div>
        </form>
      </dialog>
      <ReauthModal {...reauthModal} />
    </>
  );
}
