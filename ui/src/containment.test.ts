import { describe, expect, it } from "vitest";
import { containmentBadge, containmentNamesFiltered, containmentPhase, containmentSettled } from "./containment";
import type { ContainmentState } from "./types";

const state = (over: Partial<ContainmentState>): ContainmentState => ({
  host_id: "H-1",
  contained: true,
  version: 1,
  epoch: 1,
  ...over,
});

describe("containmentPhase", () => {
  it.each([
    ["no state", null, null],
    ["never contained", state({ contained: false, version: 0 }), null],
    ["contained, nothing delivered yet", state({}), "containing"],
    ["contained, command pending", state({ delivery: { command_id: 1, status: "pending", current: true } }), "containing"],
    ["contained and applied", state({ delivery: { command_id: 1, status: "completed", current: true } }), "contained"],
    ["contained, the agent failed it", state({ delivery: { command_id: 1, status: "failed", current: true } }), "contain_failed"],
    ["contained, an expired command awaits the catch-up", state({ delivery: { command_id: 1, status: "expired", current: true } }),
      "containing"],
    ["contained, only an older command completed", state({ delivery: { command_id: 1, status: "completed", current: false } }),
      "containing"],
    ["contained, only an older command failed", state({ delivery: { command_id: 1, status: "failed", current: false } }),
      "containing"],
    ["released, not delivered", state({ contained: false, version: 2 }), "releasing"],
    ["released and applied", state({ contained: false, version: 2, delivery: { command_id: 2, status: "completed", current: true } }),
      "released"],
    ["released, the agent failed it", state({ contained: false, version: 2, delivery: { command_id: 2, status: "failed", current: true } }),
      "release_failed"],
  ])("%s", (_, input, want) => {
    expect(containmentPhase(input)).toBe(want);
  });
});

describe("containmentSettled", () => {
  it("polls only while a change is on its way", () => {
    expect(containmentSettled("containing")).toBe(false);
    expect(containmentSettled("releasing")).toBe(false);
    for (const phase of ["contained", "contain_failed", "released", "release_failed", null] as const) {
      expect(containmentSettled(phase)).toBe(true);
    }
  });
});

describe("containmentBadge", () => {
  it("labels every phase that needs attention and nothing for a released host", () => {
    expect(containmentBadge("containing")).toEqual({ label: "Containing", variant: "info" });
    expect(containmentBadge("contained")).toEqual({ label: "Contained", variant: "critical" });
    expect(containmentBadge("contain_failed")).toEqual({ label: "Containment failed", variant: "high" });
    expect(containmentBadge("releasing")).toEqual({ label: "Releasing", variant: "info" });
    expect(containmentBadge("release_failed")).toEqual({ label: "Release failed", variant: "high" });
    expect(containmentBadge("released")).toBeNull();
    expect(containmentBadge(null)).toBeNull();
  });
});

// Whether the host said the restriction on WHICH names it resolves was in force (issue #1078). A contained host whose DNS proxy is not
// running still reaches only its own resolvers, but every name they answer resolves, and nothing else in the console says so.
describe("containmentNamesFiltered", () => {
  const delivered = (result: Record<string, unknown> | undefined, current = true) =>
    state({ delivery: { command_id: 1, status: "completed", current, result } });

  it("reports what the host said", () => {
    expect(containmentNamesFiltered(delivered({ names_filtered: true }))).toBe(true);
    expect(containmentNamesFiltered(delivered({ names_filtered: false }))).toBe(false);
  });

  // null, not false. An agent or extension that predates the field says nothing, and showing that as "names are not filtered" would
  // tell an operator a host is leakier than it is.
  it.each([
    ["a result without the field", delivered({ applied: true })],
    ["no result at all", delivered(undefined)],
    ["a value that is not a boolean", delivered({ names_filtered: "yes" })],
    ["a delivery carrying an older state", delivered({ names_filtered: false }, false)],
    ["no delivery", state({})],
    ["no state", null],
  ])("reports nothing for %s", (_name, given) => {
    expect(containmentNamesFiltered(given)).toBeNull();
  });
});
