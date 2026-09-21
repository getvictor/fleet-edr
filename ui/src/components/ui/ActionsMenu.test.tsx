import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

import { ActionsMenu, type ActionsMenuItem } from "./ActionsMenu";

afterEach(() => {
  vi.restoreAllMocks();
});

function items(overrides: Partial<Record<string, () => void>> = {}): ActionsMenuItem[] {
  return [
    { label: "Edit", onSelect: overrides.Edit ?? (() => undefined) },
    { label: "Disable", title: "Pause enforcement for this rule", onSelect: overrides.Disable ?? (() => undefined) },
    { label: "Delete", dividerBefore: true, onSelect: overrides.Delete ?? (() => undefined) },
  ];
}

describe("ActionsMenu", () => {
  // The whole point of the control: a row's actions are not in the document until asked for, so they cannot read as one run of
  // text, and each gets a target of its own.
  it("keeps its actions closed until the trigger is pressed", () => {
    render(<ActionsMenu label="Actions for rule-1" items={items()} />);

    expect(screen.queryByRole("button", { name: "Edit" })).toBeNull();
    const trigger = screen.getByRole("button", { name: "Actions for rule-1" });
    expect(trigger).toHaveAttribute("aria-expanded", "false");

    fireEvent.click(trigger);
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("button", { name: "Edit" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Delete" })).toBeVisible();
  });

  // Choosing an action closes the menu. Left open, the panel covers the rows beneath it and the next row an operator reaches for
  // is the one the menu is sitting on top of.
  it("runs the chosen action and closes", () => {
    const onEdit = vi.fn();
    render(<ActionsMenu label="Actions for rule-1" items={items({ Edit: onEdit })} />);

    fireEvent.click(screen.getByRole("button", { name: "Actions for rule-1" }));
    fireEvent.click(screen.getByRole("button", { name: "Edit" }));

    expect(onEdit).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("button", { name: "Disable" })).toBeNull();
  });

  // The destructive item is set apart by a rule above it rather than by colour, so a click aimed at the item above cannot land on
  // it. The warning itself belongs on the confirmation that follows.
  it("separates the destructive item from the ones above it", () => {
    render(<ActionsMenu label="Actions for rule-1" items={items()} />);
    fireEvent.click(screen.getByRole("button", { name: "Actions for rule-1" }));

    expect(screen.getByRole("button", { name: "Delete" }).className).toContain("actions-menu__item--divided");
    expect(screen.getByRole("button", { name: "Edit" }).className).not.toContain("actions-menu__item--divided");
  });

  // The trigger reads the same on every row, so the row it belongs to has to come from its accessible name; otherwise a screen
  // reader hears "Actions" repeated down the column with nothing to tell the rows apart.
  it("names the trigger for the row it belongs to", () => {
    render(<ActionsMenu label="Actions for /bin/sh" items={items()} />);
    expect(screen.getByRole("button", { name: "Actions for /bin/sh" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Actions for /bin/sh" })).toHaveTextContent("Actions");
  });

  // The table this sits in scrolls sideways, so it carries overflow-x, which makes it clip vertically too. A panel laid out inside
  // that box is cut off on the lower rows. Fixed positioning is what takes it out of the table's clip.
  // What is asserted here is the half the component owns: the panel is given measured viewport coordinates rather than being laid
  // out by the row. The other half, `position: fixed` in the stylesheet, is what those coordinates mean, and jsdom loads no CSS, so
  // that is verified in a browser instead.
  it("places the panel at measured viewport coordinates rather than inside the row", () => {
    render(<ActionsMenu label="Actions for rule-1" items={items()} />);
    fireEvent.click(screen.getByRole("button", { name: "Actions for rule-1" }));

    const panel = screen.getByRole("button", { name: "Edit" }).parentElement as HTMLElement;
    expect(panel.style.top).not.toBe("");
    expect(panel.style.right).not.toBe("");
    // Measured, so it is placed rather than left at the window's corner behind the visibility guard.
    expect(panel.style.visibility).not.toBe("hidden");
  });

  // A fixed panel does not travel with the row it was opened from, so a scroll would leave it hanging over whichever row slid
  // underneath. The scroll that matters is the table wrapper's own, which does not bubble, hence the capture-phase listener.
  it("closes when something scrolls underneath it", () => {
    render(<ActionsMenu label="Actions for rule-1" items={items()} />);
    fireEvent.click(screen.getByRole("button", { name: "Actions for rule-1" }));
    expect(screen.getByRole("button", { name: "Edit" })).toBeVisible();

    fireEvent.scroll(window);
    expect(screen.queryByRole("button", { name: "Edit" })).toBeNull();
  });

  it("carries an item's explanation as its hover title", () => {
    render(<ActionsMenu label="Actions for rule-1" items={items()} />);
    fireEvent.click(screen.getByRole("button", { name: "Actions for rule-1" }));
    expect(screen.getByRole("button", { name: "Disable" })).toHaveAttribute("title", "Pause enforcement for this rule");
  });
});
