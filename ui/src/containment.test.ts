import { describe, expect, it } from "vitest";
import { containmentBadge, containmentPhase, containmentSettled, nameFiltering } from "./containment";
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

// What the host's live health says about the restriction on which names it resolves (issue #1078). Read from health rather than from
// the containment command's result, which freezes when that command completes and cannot see a proxy that stopped later.
describe("nameFiltering", () => {
  it("reports the operator having switched the proxy off, which the host states directly", () => {
    expect(nameFiltering([{ type: "dns_proxy", reason: "provider_disabled" }])).toBe("disabled");
  });

  // The case a lifecycle state cannot see: a wedged provider still reports itself running, so only the server's derived signal
  // catches it. Reported apart from the definite one, because it is evidence and not proof.
  it("reports the server having seen no DNS capture, separately", () => {
    expect(nameFiltering([{ type: "dns_proxy_delivery", reason: "no_flow_telemetry" }])).toBe("no-capture");
  });

  // The host's own statement wins: it is definite where the derived signal is inferred.
  it("prefers what the host says over what the server infers", () => {
    expect(
      nameFiltering([
        { type: "dns_proxy_delivery", reason: "no_flow_telemetry" },
        { type: "dns_proxy", reason: "provider_disabled" },
      ]),
    ).toBe("disabled");
  });

  it.each([
    ["the proxy is capturing", [{ type: "dns_proxy", reason: "activated" }]],
    ["the proxy is stopped by a fault, which the health section already reports", [{ type: "dns_proxy", reason: "provider_stopped" }]],
    ["nothing is said about DNS at all", [{ type: "content_filter", reason: "activated" }]],
    ["no components at all", []],
  ])("reports filtering when %s", (_name, conditions) => {
    expect(nameFiltering(conditions)).toBe("filtering");
  });

  // null, not "filtering": a page that has not read health yet must not be shown as either.
  it.each([
    ["health is not read yet", null],
    ["health is absent", undefined],
  ])("reports nothing when %s", (_name, conditions) => {
    expect(nameFiltering(conditions)).toBeNull();
  });
});
