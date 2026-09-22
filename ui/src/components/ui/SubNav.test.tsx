import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";

import { SubNav } from "./SubNav";
import { RULES_TABS, RULES_TABS_LABEL } from "../rulesTabs";

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <SubNav items={RULES_TABS} label={RULES_TABS_LABEL} />
    </MemoryRouter>,
  );
}

describe("SubNav", () => {
  // spec:web-ui/coverage-is-read-beside-the-rules-it-is-computed-from/each-surface-offers-the-other
  it("offers both surfaces of the section and marks the one being read", () => {
    renderAt("/rules");

    const rules = screen.getByRole("link", { name: "Rules" });
    const coverage = screen.getByRole("link", { name: "ATT&CK coverage" });
    expect(rules).toHaveAttribute("aria-current", "page");
    expect(coverage).not.toHaveAttribute("aria-current");
    // Each is a real route, so the surface can be linked to and reloaded rather than reached only by clicking through.
    expect(coverage).toHaveAttribute("href", "/coverage");
  });

  it("marks coverage when that is the surface being read", () => {
    renderAt("/coverage");

    expect(screen.getByRole("link", { name: "ATT&CK coverage" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: "Rules" })).not.toHaveAttribute("aria-current");
  });

  // A rule's detail sits below the catalogue, so the row keeps saying which surface of the section the operator is inside rather
  // than going blank the moment they open a rule.
  it("keeps the catalogue marked on a surface below it", () => {
    renderAt("/rules/dyld_insert");

    expect(screen.getByRole("link", { name: "Rules" })).toHaveAttribute("aria-current", "page");
  });

  // A nav of links rather than an ARIA tablist: the tablist role promises arrow-key movement between tabs and a tabpanel
  // relationship this does not implement, and the host page's own view switch is documented as making the same choice.
  it("is a navigation landmark rather than a tablist", () => {
    renderAt("/rules");

    expect(screen.getByRole("navigation", { name: RULES_TABS_LABEL })).toBeVisible();
    expect(screen.queryByRole("tablist")).toBeNull();
  });
});
