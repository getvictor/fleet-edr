import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AttackCoverage } from "./AttackCoverage";
import * as api from "../api";
import type { AttackNavigatorLayer } from "../api";

// AttackCoverage had no component test before the StatCard extraction. These
// pin the summary strip (now the shared StatCard/SummaryStrip primitive) so the
// refactor stays covered: three metric cards with the covered-technique,
// distinct-rule and tactic counts derived from the layer.
const layer: AttackNavigatorLayer = {
  name: "Fleet EDR coverage",
  versions: { layer: "4.5", navigator: "5.0.0" },
  domain: "enterprise-attack",
  description: "",
  filters: { platforms: ["macOS"] },
  techniques: [
    // score is 1 (binary coverage) to match the server's Navigator layer builder; the component ignores score, but the fixture
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
    expect(within(cardFor("techniques covered")).getByText("2")).toBeInTheDocument();
    // rule_a + rule_b are the two distinct covering rules across both techniques.
    expect(within(cardFor("detection rules")).getByText("2")).toBeInTheDocument();
    expect(within(cardFor("tactics with coverage")).getByText("2")).toBeInTheDocument();
  });
});
