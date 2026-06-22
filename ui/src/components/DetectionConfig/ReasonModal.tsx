import { useEffect, useRef, useState } from "react";
import { Button } from "../ui/Button";

interface ReasonModalProps {
  readonly title: string;
  readonly description?: string;
  readonly confirmLabel: string;
  // confirmVariant tints the confirm button: `alert` (red) for the most reducing action (disable), `primary` otherwise.
  readonly confirmVariant?: "primary" | "alert";
  readonly busy?: boolean;
  readonly error?: string | null;
  // onConfirm receives the trimmed reason; the parent runs the mutation and keeps this modal mounted (busy) until it settles.
  readonly onConfirm: (reason: string) => void;
  readonly onCancel: () => void;
}

const TITLE_ID = "dc-reason-modal-title";

// ReasonModal collects a required operator reason before a coverage-reducing detection-config change (setting a rule to monitor or
// disabled) is applied, so the audit row carries the operator's actual justification instead of a generated string. It is rendered
// only while a change is pending (mount == open); the native <dialog> supplies the backdrop, focus trap, and Escape-to-cancel.
export function ReasonModal({
  title,
  description,
  confirmLabel,
  confirmVariant = "primary",
  busy = false,
  error = null,
  onConfirm,
  onCancel,
}: ReasonModalProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const [reason, setReason] = useState("");

  // Mount == open: the parent renders this only while a change is pending. showModal() opens it; the backdrop-click + Escape
  // (cancel event) listeners are attached imperatively rather than as JSX onClick/onCancel, because assigning mouse/keyboard
  // handlers to the non-interactive <dialog> in JSX trips jsx-a11y (Sonar S6847/S1082). Both dismissals are ignored while busy so
  // an in-flight confirm can't be dismissed. Re-runs on busy/onCancel change re-bind the closure; showModal is guarded on !open.
  useEffect(() => {
    const dlg = dialogRef.current;
    if (!dlg) return undefined;
    if (!dlg.open) dlg.showModal();
    const onCancelEvt = (e: Event) => { e.preventDefault(); if (!busy) onCancel(); };
    const onBackdrop = (e: MouseEvent) => { if (!busy && e.target === dlg) onCancel(); };
    dlg.addEventListener("cancel", onCancelEvt);
    dlg.addEventListener("click", onBackdrop);
    return () => {
      dlg.removeEventListener("cancel", onCancelEvt);
      dlg.removeEventListener("click", onBackdrop);
    };
  }, [busy, onCancel]);

  const trimmed = reason.trim();

  return (
    <dialog ref={dialogRef} className="dc-reason-modal" aria-labelledby={TITLE_ID}>
      <h2 id={TITLE_ID} className="dc-reason-modal__title">{title}</h2>
      {description !== undefined && <p className="dc-reason-modal__desc">{description}</p>}
      {error && <div className="detection-config__error" role="alert">{error}</div>}
      <form className="dc-reason-modal__form" onSubmit={(e) => { e.preventDefault(); if (trimmed) onConfirm(trimmed); }}>
        <label htmlFor="dc-reason-modal-input" className="dc-reason-modal__label">Reason (required for audit log)</label>
        <textarea
          id="dc-reason-modal-input"
          className="dc-reason-modal__input"
          rows={3}
          value={reason}
          onChange={(e) => { setReason(e.target.value); }}
          disabled={busy}
          autoFocus
          placeholder="Why are you reducing this rule's alerting?"
        />
        <div className="dc-reason-modal__actions">
          <Button type="button" variant="text-link" onClick={onCancel} disabled={busy}>Cancel</Button>
          <Button type="submit" variant={confirmVariant} disabled={busy || trimmed.length === 0} isLoading={busy}>
            {confirmLabel}
          </Button>
        </div>
      </form>
    </dialog>
  );
}
