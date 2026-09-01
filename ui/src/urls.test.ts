import { describe, it, expect } from "vitest";
import { isHTTPURL } from "./urls";

// isHTTPURL gates whether untrusted text becomes a followable link, so these are security assertions rather than parsing ones.
// It was extracted from two components that each had their own copy under the SAME name with different behaviour (issue #765
// review); the table below is the stronger of the two semantics, which is now what both callers get.
describe("isHTTPURL", () => {
  it.each([
    ["https://redcanary.com/blog/applescript/", true, "an ordinary https URL"],
    ["http://example.com/x", true, "http is allowed too; these are citations, not credentials"],
    // ASCII spaces are stripped by the URL parser itself, so this case does NOT exercise the trim.
    ["  https://example.com/x  ", true, "surrounding ASCII whitespace"],
    // This one does. The parser strips only C0 controls and space, while String.trim also strips Unicode whitespace, so a
    // non-breaking space (the kind that arrives when a citation is pasted out of a web page) throws without the trim and parses
    // with it. Without this row, deleting the .trim() call leaves the whole table green.
    ["\u00A0https://example.com/x\u00A0", true, "a non-breaking space is trimmed before parsing"],
    ["javascript:alert(1)", false, "a script URL is the reason this function exists"],
    ["data:text/html;base64,PHNjcmlwdD4=", false, "a data URL can carry markup"],
    ["vbscript:msgbox(1)", false, "an allowlist rejects schemes nobody enumerated"],
    ["file:///etc/passwd", false, "a local-file URL is not a citation"],
    // Not a bug: the WHATWG parser promotes the first path segment, so this IS http://just/a/path. Asserted so the "empty host"
    // guard both original copies carried is not reinstated on a hunch; it cannot fire for these schemes.
    ["http:///just/a/path", true, "empty authority is normalised, not rejected"],
    ["http://", false, "a genuinely hostless URL throws in the parser"],
    ["/relative/path", false, "not absolute"],
    ["Internal research note, 2026", false, "free text"],
    ["", false, "empty"],
  ])("%s -> %s (%s)", (input, want) => {
    expect(isHTTPURL(input)).toBe(want);
  });
});
