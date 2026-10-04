import { describe, it, expect, vi, afterEach } from "vitest";
import { downloadText } from "./download";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("downloadText", () => {
  it("saves the text under the given name and releases the object URL", async () => {
    const created = vi.fn(() => "blob:edr-test");
    const revoked = vi.fn();
    vi.stubGlobal("URL", { createObjectURL: created, revokeObjectURL: revoked });
    let clicked: { download: string; href: string } | null = null;
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      clicked = { download: this.download, href: this.getAttribute("href") ?? "" };
    });

    downloadText("title: x\n", "rule.yml", "application/yaml");

    expect(clicked).toEqual({ download: "rule.yml", href: "blob:edr-test" });
    const blob = (created.mock.calls[0] as unknown as [Blob])[0];
    expect(blob.type).toBe("application/yaml");
    expect(await blob.text()).toBe("title: x\n");
    expect(revoked).toHaveBeenCalledWith("blob:edr-test");
    expect(document.querySelector("a[download]")).toBeNull();
    vi.unstubAllGlobals();
  });
});
