import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { useDismiss } from "./useDismiss";
import "./ActionsMenu.scss";

// PANEL_GAP is the space between the trigger and the panel it opens, in pixels. A number rather than a class, because the panel is
// positioned against the viewport and the offset has to be part of that arithmetic.
const PANEL_GAP = 4;

export interface ActionsMenuItem {
  readonly label: string;
  readonly onSelect: () => void;
  // title is the hover explanation for an item whose effect its label does not fully carry, e.g. what pausing a rule does.
  readonly title?: string;
  // dividerBefore separates an item from the ones above it. Used for the destructive item at the foot of the menu, so it cannot be
  // hit by a click aimed at the item above.
  readonly dividerBefore?: boolean;
}

interface ActionsMenuProps {
  readonly items: readonly ActionsMenuItem[];
  // label names the trigger for assistive technology, e.g. "Actions for /bin/sh". The visible text is always "Actions", which would
  // otherwise repeat identically down the whole column.
  readonly label: string;
}

// ActionsMenu collapses a row's actions into one control.
//
// Rendered inline, several actions in a cell read as one run of text rather than as separate targets: four link-styled buttons a few
// pixels apart are one green sentence, and on a narrow column they wrap mid-run so a row's actions break in an arbitrary place. One
// trigger per row keeps the row's height fixed and gives every action a full-width target of its own.
//
// A labelled trigger rather than an ellipsis or kebab glyph: "Actions" says what the control is without the operator having to have
// learned the glyph, and it is what the product this one lives beside does.
//
// Implemented as a disclosure (the trigger carries aria-expanded) rather than the ARIA menu pattern, matching AccountMenu: the items
// are plain buttons, so menu/menuitem roles would promise arrow-key navigation this does not implement. Tab reaches every item.
export function ActionsMenu({ items, label }: ActionsMenuProps) {
  const { open, setOpen, ref } = useDismiss<HTMLDivElement>();
  const triggerRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ top: number; right: number } | null>(null);
  const panelID = useId();

  // The panel is positioned against the VIEWPORT rather than against the row, because the table it lives in scrolls sideways and so
  // carries overflow-x: auto. A box with overflow on one axis computes the other to auto as well, so the table clips vertically too:
  // measured before this, the menu on the last row ran 153px past the wrapper's bottom edge and was simply not visible. A fixed box
  // is not clipped by an ancestor's overflow, which is what gets the panel out of the table.
  //
  // Fixed rather than moved into document.body, which is the other way out of a clipping ancestor: the panel stays inside the root
  // this component's outside-click handler watches, so a click on one of its own items still counts as a click inside.
  //
  // Measured rather than estimated, and after the panel is in the document: its height depends on how many actions the operator's
  // permissions left in it, so a constant would flip the wrong way for a two-item menu.
  //
  // The measurement has to be written back as state, which is what the set-state-in-effect rule is about: there is no way to know a
  // box's height before it is laid out, so a render, a measure and a second render is the shape this takes.
  /* eslint-disable react-hooks/set-state-in-effect -- position is measured from the laid-out panel, so it cannot be derived */
  useLayoutEffect(() => {
    if (!open) {
      setPos(null);
      return;
    }
    const trigger = triggerRef.current;
    const panel = panelRef.current;
    if (!trigger || !panel) return;
    const rect = trigger.getBoundingClientRect();
    const height = panel.offsetHeight;
    const below = rect.bottom + PANEL_GAP;
    // Opens upward when it would otherwise run off the bottom of the window, unless there is even less room above it.
    const above = rect.top - PANEL_GAP - height;
    const flip = below + height > window.innerHeight && above >= 0;
    setPos({ top: flip ? above : below, right: window.innerWidth - rect.right });
  }, [open, items.length]);
  /* eslint-enable react-hooks/set-state-in-effect */

  // A fixed panel does not travel with the row it belongs to, so a scroll would leave it pointing at whatever row slid under it.
  // Closing is the honest response: the operator can reopen on the row they can now see. Capture phase, because the scroll that
  // matters is the table wrapper's own and that does not bubble.
  useEffect(() => {
    if (!open) return undefined;
    const close = () => { setOpen(false); };
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);
    return () => {
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("resize", close);
    };
  }, [open, setOpen]);

  return (
    <div className="actions-menu" ref={ref}>
      {/* aria-expanded and aria-controls, and deliberately NOT aria-haspopup: that attribute's bare true means "menu", and a screen
          reader announcing a menu invites the arrow-key navigation the ARIA menu pattern carries. This is a disclosure of plain
          buttons reached by Tab, so claiming a menu would promise a keyboard model that is not here (#1143 review). */}
      <button
        type="button"
        ref={triggerRef}
        className="actions-menu__trigger"
        aria-expanded={open}
        aria-controls={panelID}
        aria-label={label}
        onClick={() => {
          setOpen((v) => !v);
        }}
      >
        Actions
      </button>
      {open && (
        <div
          id={panelID}
          className="actions-menu__dropdown"
          ref={panelRef}
          // Hidden for the one frame between being in the document and having been measured, so it is never painted at the top-left
          // corner of the window before moving to the row it belongs to.
          style={pos ? { top: pos.top, right: pos.right } : { visibility: "hidden" }}
        >
          {items.map((item) => (
            <button
              key={item.label}
              type="button"
              className={`actions-menu__item${item.dividerBefore ? " actions-menu__item--divided" : ""}`}
              title={item.title}
              onClick={() => {
                setOpen(false);
                item.onSelect();
              }}
            >
              {item.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
