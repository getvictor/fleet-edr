import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { AttackCoverage } from "./AttackCoverage";
import * as api from "../api";
import { PermissionsContext, PermissionAction } from "../permissions-core";
import type { AttackNavigatorLayer } from "../api";

// AttackCoverage had no component test before the StatCard extraction. These
// pin the summary strip (now the shared StatCard/SummaryStrip primitive) so the
// refactor stays covered: three metric cards with the covered-technique,
// distinct-rule and tactic counts derived from the layer.
const layer: AttackNavigatorLayer = {
  name: "Fleet EDR coverage",
  // Mirror what the server's BuildNavigatorLayer emits (attack v19, navigator 5.2.0) so the fixture stays representative of
  // the real wire shape, even though this component only reads `techniques`.
  versions: { attack: "19", navigator: "5.2.0", layer: "4.5" },
  domain: "enterprise-attack",
  description: "MITRE ATT&CK techniques covered by currently-registered Fleet EDR detection rules.",
  filters: { platforms: ["macOS"] },
  techniques: [
    // score separates coverage that alerts (1) from coverage that only records (below 1). The component reads it: most of the
    // catalog now ships in monitor mode, so one combined count would claim the product alerts on techniques it does not.
    // The original note said the component ignores score, which stopped being true when the corpus landed (issue #764). The fixture
    // should still reflect the real wire value.
    { techniqueID: "T1555.001", score: 1, comment: "Covered by: rule_a, rule_b" },
    { techniqueID: "T1059", score: 1, comment: "Covered by: rule_a" },
  ],
};

beforeEach(() => {
  vi.spyOn(api, "fetchAttackNavigatorLayer").mockResolvedValue(layer);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("AttackCoverage summary strip", () => {
  it("renders three stat cards with the derived counts", async () => {
    render(
      <MemoryRouter>
        <AttackCoverage />
      </MemoryRouter>,
    );
    const strip = await waitFor(() => {
      const el = document.querySelector(".summary-strip");
      expect(el).toBeInTheDocument();
      return el as HTMLElement;
    });
    const cards = strip.querySelectorAll(".stat-card");
    expect(cards).toHaveLength(3);

    const cardFor = (label: string) =>
      within(strip).getByText(label).closest(".stat-card") as HTMLElement;
    expect(within(cardFor("techniques alerting by default")).getByText("2")).toBeInTheDocument();
    // The hint is asserted at the CALL SITE, not only in StatCard's own test. That test proves the prop is forwarded,
    // which stays true with the prop deleted from here: the page would ship two cards with no explanation and every
    // test would still pass. What it says matters as much as that it exists, so the disabled case is pinned too, since
    // an earlier version claimed every counted rule records matches, which is false of a rule that ships disabled.
    expect(cardFor("techniques alerting by default")).toHaveAttribute(
      "title",
      expect.stringContaining("Counted from each rule's catalog default"));
    // rule_a + rule_b are the two distinct covering rules across both techniques.
    expect(within(cardFor("detection rules")).getByText("2")).toBeInTheDocument();
    expect(within(cardFor("tactics with coverage")).getByText("2")).toBeInTheDocument();
  });

  // The count that would otherwise overstate the product. The label is mode-neutral on purpose: a sub-1 score means the covering
  // rules are in monitor OR disabled, the server does not distinguish them in the score, and calling it "monitored" would misstate
  // a disabled rule, which records nothing at all. A technique the server scored below 1 is covered only by rules that
  // raise nothing as shipped, and reporting those in one "techniques covered" figure would tell a reader the product alerts on
  // techniques it merely watches. The monitored card appears only when there is something to report, so a deployment with no
  // monitor-mode rules sees the strip it saw before.
  it("counts techniques that only record separately from those that alert", async () => {
    vi.spyOn(api, "fetchAttackNavigatorLayer").mockResolvedValue({
      ...layer,
      techniques: [
        { techniqueID: "T1555.001", score: 1, comment: "Covered by: rule_a" },
        { techniqueID: "T1059", score: 0.5, comment: "No rule covering this raises an alert as shipped. Covered by: rule_b" },
        { techniqueID: "T1105", score: 0.5, comment: "No rule covering this raises an alert as shipped. Covered by: rule_c" },
      ],
    });

    render(
      <MemoryRouter>
        <AttackCoverage />
      </MemoryRouter>,
    );
    const strip = await waitFor(() => {
      const el = document.querySelector(".summary-strip");
      expect(el).toBeInTheDocument();
      return el as HTMLElement;
    });

    const cardFor = (label: string) =>
      within(strip).getByText(label).closest(".stat-card") as HTMLElement;
    expect(within(cardFor("techniques alerting by default")).getByText("1")).toBeInTheDocument();

    // The silent-rule card carries the number AND somewhere to act on it. Left bare the figure reads as a defect to switch
    // off, when those rules ship in monitor mode deliberately, so the link is part of what the card is for.
    const silent = within(strip).getByText(/techniques silent by default/).closest(".stat-card") as HTMLElement;
    expect(within(silent).getByText("2")).toBeVisible();
    // What the hint SAYS, not just that one is attached: an earlier version claimed every counted rule records matches,
    // which is false of a rule shipping disabled, and BuildNavigatorLayer gives monitor and disabled the same score.
    expect(silent).toHaveAttribute("title", expect.stringContaining("do not alert out of the box"));
    expect(silent).toHaveAttribute("title", expect.stringContaining("a few ship disabled"));
    const tune = within(silent).getByRole("link", { name: /promote or tune/i });
    expect(tune).toBeVisible();
    expect(tune).toHaveAttribute("href", "/detection-config");
  });
});

// The Coverage page is open to every operator; Detection tuning is not. Offering a link that lands on the no-access page is
// worse than not offering it, so the card keeps its number and drops the affordance.
describe("AttackCoverage tuning link", () => {
  // The card only renders when something is covered ONLY by silent rules, so the fixture needs a sub-1 score; the default
  // layer is all-alerting and would hide the card, making both assertions below pass for the wrong reason.
  beforeEach(() => {
    vi.mocked(api.fetchAttackNavigatorLayer).mockResolvedValue({
      ...layer,
      techniques: [
        { techniqueID: "T1059", score: 1, comment: "Covered by: rule_a" },
        { techniqueID: "T1016", score: 0.5, comment: "No rule covering this raises an alert as shipped. Covered by: rule_b" },
      ],
    });
  });

  const renderWithPerms = (perms: readonly string[] | undefined) =>
    render(
      <PermissionsContext.Provider value={perms}>
        <MemoryRouter>
          <AttackCoverage />
        </MemoryRouter>
      </PermissionsContext.Provider>,
    );

  it("offers the link to an operator who can reach Detection tuning", async () => {
    renderWithPerms([PermissionAction.DetectionConfigRead]);
    const link = await screen.findByRole("link", { name: /promote or tune/i });
    expect(link).toHaveAttribute("href", "/detection-config");
  });

  // spec:web-ui/att-ck-coverage-page/a-tuning-action-is-offered-only-where-it-can-be-followed
  it("withholds the link, but not the number, from an operator who cannot", async () => {
    renderWithPerms([]);
    // The count still renders: it is the fact worth knowing even for someone who cannot act on it themselves.
    expect(await screen.findByText(/techniques silent by default/)).toBeVisible();
    expect(screen.queryByRole("link", { name: /promote or tune/i })).not.toBeInTheDocument();
  });
});

// A technique belongs to every tactic ATT&CK gives it. Listing it under only the first made the others look uncovered when a
// rule covers them, and the upstream matrix repeats the technique the same way.
describe("AttackCoverage multi-tactic techniques", () => {
  // spec:web-ui/att-ck-coverage-page/a-technique-appears-under-every-tactic-it-belongs-to
  it("lists a multi-tactic technique under each of its tactics", async () => {
    vi.mocked(api.fetchAttackNavigatorLayer).mockResolvedValue({
      ...layer,
      // T1543.004 is Launch Daemon: Persistence AND Privilege Escalation in ATT&CK v19.
      techniques: [{ techniqueID: "T1543.004", score: 1, comment: "Covered by: rule_a" }],
    });
    render(<MemoryRouter><AttackCoverage /></MemoryRouter>);

    await waitFor(() => { expect(screen.getAllByText("T1543.004").length).toBeGreaterThan(0); });
    expect(screen.getByText("Persistence")).toBeVisible();
    expect(screen.getByText("Privilege Escalation")).toBeVisible();
    expect(screen.getAllByText("T1543.004")).toHaveLength(2);
  });
});
