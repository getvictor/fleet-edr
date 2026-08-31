import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { AttackCoverage } from "./AttackCoverage";
import * as api from "../api";
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
    expect(within(cardFor("techniques alerting")).getByText("2")).toBeInTheDocument();
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
    expect(within(cardFor("techniques alerting")).getByText("1")).toBeInTheDocument();
    expect(within(cardFor("techniques not alerting")).getByText("2")).toBeInTheDocument();
  });
});
