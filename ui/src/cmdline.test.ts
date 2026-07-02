import { describe, it, expect } from "vitest";

import { formatCommandLine } from "./cmdline";

describe("formatCommandLine", () => {
  const cases: { name: string; args: string[] | undefined; path: string; want: string }[] = [
    { name: "plain args join with spaces", args: ["curl", "-s", "https://x"], path: "/usr/bin/curl", want: "curl -s https://x" },
    {
      name: "an argument containing a space is quoted so argv boundaries stay visible",
      args: ["open", "/Users/v/My Documents/report.pdf"],
      path: "/usr/bin/open",
      want: 'open "/Users/v/My Documents/report.pdf"',
    },
    { name: "inner double quotes are escaped", args: ["say", 'he said "hi"'], path: "/usr/bin/say", want: 'say "he said \\"hi\\""' },
    { name: "an empty argument stays visible", args: ["tool", ""], path: "/t", want: 'tool ""' },
    { name: "no args falls back to the path", args: undefined, path: "/sbin/launchd", want: "/sbin/launchd" },
    { name: "no args and no path reads unknown", args: [], path: "", want: "(unknown)" },
  ];
  it.each(cases)("$name", ({ args, path, want }) => {
    expect(formatCommandLine(args, path)).toBe(want);
  });
});
