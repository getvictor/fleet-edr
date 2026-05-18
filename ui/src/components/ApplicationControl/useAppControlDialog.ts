import { useCallback, useEffect, useRef } from "react";

// useAppControlDialog encapsulates the open/close + backdrop + escape-to-cancel wiring every app-control modal repeats. Sonar flagged
// the duplicated useEffect blocks across AddRuleModal / EditRuleModal / ConfirmActionModal as a new_duplicated_lines_density
// violation on PR #189; collapsing the scaffolding here brings every modal under one helper.
//
// Returns {dialogRef, handleCancel}. The caller passes dialogRef into <dialog ref={dialogRef}> and handleCancel into <dialog
// onCancel>. The hook owns the showModal()/close() lifecycle keyed on `open` AND the backdrop-click handler that routes through
// onClose so the parent's open state stays the single source of truth.
//
// Test note: in JSDOM, HTMLDialogElement.prototype.showModal / .close need polyfills (the existing AddRuleModal.test.tsx +
// PolicyDetail.test.tsx setup blocks already supply them via prototype assignment).
export function useAppControlDialog(open: boolean, onClose: () => void) {
  const dialogRef = useRef<HTMLDialogElement>(null);

  // Open / close the native <dialog>. showModal() is what gives us backdrop + focus trap + Escape-to-cancel for free; the
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

  // Escape (via dialog's onCancel event) routes through this so the parent's open-state stays authoritative.
  const handleCancel = useCallback((e: React.SyntheticEvent<HTMLDialogElement>) => {
    e.preventDefault();
    onClose();
  }, [onClose]);

  // Backdrop click: native <dialog> does not fire close on backdrop click; we synthesize it by detecting clicks whose target IS
  // the dialog element itself (content clicks have a child target).
  useEffect(() => {
    const dlg = dialogRef.current;
    if (!dlg) return undefined;
    const onBackdrop = (e: MouseEvent) => {
      if (e.target === dlg) onClose();
    };
    dlg.addEventListener("click", onBackdrop);
    return () => { dlg.removeEventListener("click", onBackdrop); };
  }, [onClose]);

  return { dialogRef, handleCancel };
}
