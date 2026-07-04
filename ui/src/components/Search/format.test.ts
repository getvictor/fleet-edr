import { describe, it, expect } from "vitest";
import { basename, hostPort, formatNs } from "./format";

describe("basename", () => {
  it("returns the last segment for a POSIX path", () => {
    expect(basename("/usr/bin/curl")).toBe("curl");
  });

  it("handles a Windows-style backslash separator", () => {
    expect(basename("C:\\Windows\\System32\\cmd.exe")).toBe("cmd.exe");
  });

  it("returns the whole string when there is no separator", () => {
    expect(basename("bash")).toBe("bash");
  });
});

describe("hostPort", () => {
  it("joins an IPv4 address and port with a colon", () => {
    expect(hostPort("1.2.3.4", 443)).toBe("1.2.3.4:443");
  });

  it("brackets an IPv6 address so the port colon is unambiguous", () => {
    expect(hostPort("2606::1", 443)).toBe("[2606::1]:443");
  });

  it("passes a hostname through unbracketed", () => {
    expect(hostPort("example.com", 80)).toBe("example.com:80");
  });
});

describe("formatNs", () => {
  it("renders an ns-since-epoch timestamp as a locale string", () => {
    // 1_000_000_000 ns = 1_000 ms = 1970-01-01T00:00:01Z; assert it is a non-empty, parseable rendering.
    const out = formatNs(1_000_000_000);
    expect(out).toBeTruthy();
    expect(new Date(out).getTime()).not.toBeNaN();
  });
});
