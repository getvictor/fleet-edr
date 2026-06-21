import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { CopyButton } from "./CopyButton";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("CopyButton", () => {
  it("copies the value and flips the title to Copied", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    render(<CopyButton value="edrsa_secret" label="Copy client secret" />);
    const btn = screen.getByRole("button", { name: "Copy client secret" });
    expect(btn).toHaveAttribute("title", "Copy");
    fireEvent.click(btn);
    await waitFor(() => { expect(writeText).toHaveBeenCalledWith("edrsa_secret"); });
    await waitFor(() => { expect(btn).toHaveAttribute("title", "Copied"); });
  });

  it("does not throw without a clipboard API", () => {
    vi.stubGlobal("navigator", {});
    render(<CopyButton value="x" label="Copy x" />);
    expect(() => { fireEvent.click(screen.getByRole("button", { name: "Copy x" })); }).not.toThrow();
  });
});
