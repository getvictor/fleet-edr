import { useEffect, useRef, useState } from "react";
import "./CopyButton.scss";

// COPIED_FEEDBACK_MS is how long the button shows the "Copied" check before reverting to the clipboard icon.
const COPIED_FEEDBACK_MS = 1500;

interface CopyButtonProps {
  readonly value: string;
  // label is the accessible name, e.g. "Copy client secret"; the visible affordance is an icon only.
  readonly label: string;
}

// CopyButton is the standard copy-to-clipboard affordance: an icon button (clipboard, swapping to a check on success) with an
// accessible label. navigator.clipboard is undefined in insecure contexts / older browsers (the lib type claims otherwise, hence the
// cast); the adjacent field stays selectable as a fallback.
export function CopyButton({ value, label }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);

  async function handleCopy() {
    const clipboard = navigator.clipboard as Clipboard | undefined;
    if (!clipboard) return;
    try {
      await clipboard.writeText(value);
      setCopied(true);
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => { setCopied(false); }, COPIED_FEEDBACK_MS);
    } catch {
      // Clipboard unavailable; the source field stays selectable.
    }
  }

  return (
    <>
      <button
        type="button"
        className="copy-button"
        aria-label={label}
        title={copied ? "Copied" : "Copy"}
        onClick={() => { void handleCopy(); }}
      >
        {copied ? (
          <svg
            className="copy-button__icon" viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"
            fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"
          >
            <path d="M13 4.5 6.5 11 3 7.5" />
          </svg>
        ) : (
          <svg
            className="copy-button__icon" viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"
            fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"
          >
            <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
            <path d="M3.5 10.5H3A1.5 1.5 0 0 1 1.5 9V3A1.5 1.5 0 0 1 3 1.5h6A1.5 1.5 0 0 1 10.5 3v.5" />
          </svg>
        )}
      </button>
      {/* Screen-reader confirmation: the title swap alone is not reliably announced. */}
      <span className="copy-button__live" role="status" aria-live="polite">{copied ? "Copied" : ""}</span>
    </>
  );
}
