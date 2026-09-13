import { describe, it, expect } from "vitest";
import { BINDABLE_ROLES, roleLabel } from "./roles";

describe("roleLabel", () => {
  it("labels every seeded role, and the absence of one", () => {
    expect(roleLabel("analyst")).toBe("Analyst");
    expect(roleLabel("senior_analyst")).toBe("Senior analyst");
    expect(roleLabel("auditor")).toBe("Auditor");
    expect(roleLabel("admin")).toBe("Admin");
    expect(roleLabel("super_admin")).toBe("Super admin");
    expect(roleLabel("")).toBe("No role");
  });

  it("shows a role this build does not know as its id", () => {
    expect(roleLabel("custom_responder")).toBe("custom_responder");
  });

  it("never offers super_admin for binding", () => {
    expect(BINDABLE_ROLES.map((r) => r.value)).toEqual(["analyst", "senior_analyst", "auditor", "admin"]);
  });
});
