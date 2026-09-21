import { useDismiss } from "./useDismiss";
import "./ActionsMenu.scss";

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

  return (
    <div className="actions-menu" ref={ref}>
      <button
        type="button"
        className="actions-menu__trigger"
        aria-haspopup="true"
        aria-expanded={open}
        aria-label={label}
        onClick={() => {
          setOpen((v) => !v);
        }}
      >
        Actions
        <span className={`actions-menu__chevron${open ? " actions-menu__chevron--open" : ""}`} aria-hidden="true">
          &#9654;
        </span>
      </button>
      {open && (
        <div className="actions-menu__dropdown">
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
