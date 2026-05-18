import type { ReactNode, SyntheticEvent } from "react";
import { Button, type ButtonVariant } from "../ui/Button";
import { useAppControlDialog } from "./useAppControlDialog";
import "./ApplicationControl.scss";

interface AppControlDialogShellProps {
  // open mirrors the parent's open prop. The shell uses the shared useAppControlDialog hook to wire showModal/close + cancel +
  // backdrop click handling.
  readonly open: boolean;
  readonly onClose: () => void;
  // titleId + title + subtitle render the dialog header.
  readonly titleId: string;
  readonly title: string;
  readonly subtitle?: ReactNode;
  // formError + isBusy + submitDisabled control the action buttons row + the inline error display.
  readonly formError: string | null;
  readonly busy: boolean;
  readonly submitDisabled: boolean;
  readonly submitLabel: string;
  readonly submitBusyLabel?: string;
  readonly submitVariant?: ButtonVariant;
  readonly onSubmit: (e: SyntheticEvent) => void;
  // children renders the per-form inputs between the error box and the action buttons.
  readonly children: ReactNode;
  // reauthModal lets the caller mount useReauthRetry's modal as a sibling without leaking the dialog scaffolding above.
  readonly reauthModal?: ReactNode;
}

// AppControlDialogShell wraps the duplicated dialog scaffolding (header + error box + form + action buttons + reauth modal) the
// three app-control modals share. Per-modal form fields live in `children`. Sonar flagged the scaffold duplication on PR #189 as
// 17.3% new_duplicated_lines_density (threshold 3%); collapsing here cuts the per-modal LOC by ~25 lines and brings the density
// under the threshold while preserving the modal-specific copy + form fields in the caller.
export function AppControlDialogShell({
  open,
  onClose,
  titleId,
  title,
  subtitle,
  formError,
  busy,
  submitDisabled,
  submitLabel,
  submitBusyLabel,
  submitVariant,
  onSubmit,
  children,
  reauthModal,
}: AppControlDialogShellProps) {
  const { dialogRef, handleCancel } = useAppControlDialog(open, onClose);
  return (
    <>
      <dialog
        ref={dialogRef}
        className="app-control-dialog"
        aria-labelledby={titleId}
        onCancel={handleCancel}
      >
        <div className="app-control-dialog__header">
          <h2 id={titleId} className="app-control-dialog__title">{title}</h2>
          {subtitle !== undefined && (
            <p className="app-control-dialog__subtitle">{subtitle}</p>
          )}
        </div>

        {formError && (
          <div className="app-control-dialog__error" role="alert">
            {formError}
          </div>
        )}

        <form onSubmit={onSubmit} className="app-control-dialog__form">
          {children}

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
              variant={submitVariant}
              disabled={submitDisabled}
              isLoading={busy}
            >
              {busy ? (submitBusyLabel ?? "Saving…") : submitLabel}
            </Button>
          </div>
        </form>
      </dialog>
      {reauthModal}
    </>
  );
}
