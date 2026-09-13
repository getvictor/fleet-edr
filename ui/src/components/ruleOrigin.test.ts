import { describe, expect, it } from "vitest";
import { isLocallyAuthored } from "./ruleOrigin";

describe("isLocallyAuthored", () => {
  it("is true only for the origin the server reports for the deployment's own rules", () => {
    expect(isLocallyAuthored("Locally authored")).toBe(true);
    expect(isLocallyAuthored("SigmaHQ, by Someone")).toBe(false);
    expect(isLocallyAuthored("Fleet EDR")).toBe(false);
  });

  it("does not claim a rule whose origin was not reported", () => {
    expect(isLocallyAuthored(undefined)).toBe(false);
  });
});
