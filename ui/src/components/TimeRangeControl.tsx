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
  readonly onChange: (next: TimeWindow) => void;
}

// TimeRangeControl is the host page's single at-rest time affordance (issue #581): one button labeled with the active window,
// flanked by shift arrows that move the window by its own width. The popover offers the relative quick-picks and an absolute
// from/to selection (native datetime-local: keyboard-friendly, no dependency; second-precision narrowing comes from the histogram).
export function TimeRangeControl({ window: activeWindow, onChange }: TimeRangeControlProps) {
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

  const toggle = () => {
    if (!open) {
      const bounds = windowBounds(activeWindow, Date.now());
      setDraftFrom(nsToLocalInput(bounds.fromNs));
      setDraftTo(nsToLocalInput(bounds.toNs));
    }
    setOpen((o) => !o);
  };

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
        onClick={() => { onChange(shiftWindow(activeWindow, -1, Date.now())); }}
      >
        &larr;
      </Button>
      <button
        type="button"
        className="time-range__label"
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={toggle}
      >
        {windowLabel(activeWindow)}
      </button>
      <Button
        size="small"
        variant="inverse"
        aria-label="Shift time window forward"
        onClick={() => { onChange(shiftWindow(activeWindow, 1, Date.now())); }}
      >
        &rarr;
      </Button>

      {open && (
        <div className="time-range__popover" role="dialog" aria-label="Select time range">
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
              From
              <input type="datetime-local" value={draftFrom} onChange={(e) => { setDraftFrom(e.target.value); }} />
            </label>
            <label>
              To
              <input type="datetime-local" value={draftTo} onChange={(e) => { setDraftTo(e.target.value); }} />
            </label>
            <Button size="small" onClick={applyAbsolute}>
              Apply
            </Button>
          </div>
        </div>
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
  if (!value) return null;
  const ms = new Date(value).getTime();
  return Number.isFinite(ms) ? ms * NANOSECONDS_PER_MILLISECOND : null;
}
