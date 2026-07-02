import { describe, it, expect } from "vitest";

import { firstPermittedRoute } from "./nav-links";
import { PermissionAction } from "../../permissions-core";

describe("firstPermittedRoute", () => {
  const cases: { name: string; permissions: string[]; expected: string }[] = [
    {
      name: "alert.read lands on Alerts",
      permissions: [PermissionAction.AlertRead, PermissionAction.HostRead, PermissionAction.AppControlRead],
      expected: "/alerts",
    },
    { name: "host.read without alert.read lands on Hosts", permissions: [PermissionAction.HostRead], expected: "/hosts" },
    // spec:web-ui/alert-list-is-the-home-view/operator-without-alert-read-lands-on-their-first-permitted-surface
    {
      name: "app-control-only operator lands on Application control",
      permissions: [PermissionAction.AppControlRead],
      expected: "/app-control",
    },
    { name: "an empty permission set lands on the ungated Coverage", permissions: [], expected: "/coverage" },
  ];
  it.each(cases)("$name", ({ permissions, expected }) => {
    const can = (action: string) => permissions.includes(action);
    expect(firstPermittedRoute(can)).toBe(expected);
  });
});
