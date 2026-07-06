import { useEffect, useRef, useState, type Dispatch, type RefObject, type SetStateAction } from "react";

// useDismiss manages a click-open disclosure/popover: an `open` flag, the container ref, and auto-close on an outside mousedown or the
// Escape key. Extracted so the identical outside-click/Escape wiring lives in one place instead of being copied into each popover (the
// account menu, the host header's Details popover, and any future disclosure); Sonar flagged the copies as duplication. Attach the
// returned ref to the popover's root element so an outside click is detected as "not contained by ref".
export function useDismiss<T extends HTMLElement>(): {
  readonly open: boolean;
  readonly setOpen: Dispatch<SetStateAction<boolean>>;
  readonly ref: RefObject<T | null>;
} {
  const [open, setOpen] = useState(false);
  const ref = useRef<T>(null);

  useEffect(() => {
    if (!open) return undefined;
    function onDocClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onDocClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDocClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return { open, setOpen, ref };
}
