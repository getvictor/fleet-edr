import { useEffect, useRef, useState } from "react";
import "./TimeRangeControl.scss";
import {
  RELATIVE_PRESETS,
  shiftWindow,
  windowBounds,
  windowLabel,
  type TimeWindow,
} from "../timewindow";
import { NANOSECONDS_PER_MILLISECOND } from "../constants";
import { Button } from "./ui/Button";

interface TimeRangeControlProps {
  readonly window: TimeWindow;
  // nowMs is the page's frozen "now" (see ProcessTreeView): the control resolves shifts and the absolute-picker draft against it, not
  // the live clock, so the draft and the arrows always agree with the tree/histogram window actually on screen.
  readonly nowMs: number;
  readonly onChange: (next: TimeWindow) => void;
}

// TimeRangeControl is the host page's single at-rest time affordance (issue #581): one button labeled with the active window,
// flanked by shift arrows that move the window by its own width. The popover offers the relative quick-picks and an absolute
// from/to selection (native datetime-local: keyboard-friendly, no dependency; second-precision narrowing comes from the histogram).
export function TimeRangeControl({ window: activeWindow, nowMs, onChange }: TimeRangeControlProps) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  // Absolute-tab draft values, initialized from the active window each time the popover opens.
  const [draftFrom, setDraftFrom] = useState("");
  const [draftTo, setDraftTo] = useState("");

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (rootRef.current && e.target instanceof Node && !rootRef.current.contains(e.target)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  // Sync the absolute-picker draft to the active window whenever the picker is open, so an external change (a histogram click, a
  // shift) while the popover is up does not leave stale draft values behind.
  useEffect(() => {
    if (!open) return;
    const bounds = windowBounds(activeWindow, nowMs);
    /* eslint-disable react-hooks/set-state-in-effect */
    setDraftFrom(nsToLocalInput(bounds.fromNs));
    setDraftTo(nsToLocalInput(bounds.toNs));
    /* eslint-enable react-hooks/set-state-in-effect */
  }, [open, activeWindow, nowMs]);

  const applyAbsolute = () => {
    const fromNs = localInputToNs(draftFrom);
    const toNs = localInputToNs(draftTo);
    if (fromNs === null || toNs === null || fromNs >= toNs) return;
    onChange({ kind: "absolute", fromNs, toNs });
    setOpen(false);
  };

  return (
    <div className="time-range" ref={rootRef}>
      <Button
        size="small"
        variant="inverse"
        aria-label="Shift time window back"
        onClick={() => { onChange(shiftWindow(activeWindow, -1, nowMs)); }}
      >
        &larr;
      </Button>
      <button
        type="button"
        className="time-range__label"
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() => { setOpen((o) => !o); }}
      >
        {windowLabel(activeWindow)}
      </button>
      <Button
        size="small"
        variant="inverse"
        aria-label="Shift time window forward"
        onClick={() => { onChange(shiftWindow(activeWindow, 1, nowMs)); }}
      >
        &rarr;
      </Button>

      {open && (
        <dialog open className="time-range__popover" aria-label="Select time range">
          <div className="time-range__presets">
            {RELATIVE_PRESETS.map((preset) => (
              <button
                key={preset.label}
                type="button"
                className="time-range__preset"
                onClick={() => {
                  onChange({ kind: "relative", ms: preset.ms });
                  setOpen(false);
                }}
              >
                {preset.label}
              </button>
            ))}
          </div>
          <div className="time-range__absolute">
            <label>
              <span>From</span>
              <input type="datetime-local" value={draftFrom} onChange={(e) => { setDraftFrom(e.target.value); }} />
            </label>
            <label>
              <span>To</span>
              <input type="datetime-local" value={draftTo} onChange={(e) => { setDraftTo(e.target.value); }} />
            </label>
            <Button size="small" onClick={applyAbsolute}>
              Apply
            </Button>
          </div>
        </dialog>
      )}
    </div>
  );
}

// nsToLocalInput renders a ns epoch as the local-time "YYYY-MM-DDTHH:mm" shape datetime-local expects.
function nsToLocalInput(ns: number): string {
  const d = new Date(ns / NANOSECONDS_PER_MILLISECOND);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${String(d.getFullYear())}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function localInputToNs(value: string): number | null {
  // Parse the datetime-local components explicitly into the local-time Date constructor: `new Date("YYYY-MM-DDTHH:mm")` is parsed as
  // UTC by some engines and local by others, which would shift the selected window by the operator's offset.
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(value);
  if (!m) return null;
  const [, y, mo, d, h, min] = m.map(Number);
  const ms = new Date(y, mo - 1, d, h, min).getTime();
  return Number.isFinite(ms) ? ms * NANOSECONDS_PER_MILLISECOND : null;
}
