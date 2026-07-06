import { describe, it, expect } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useDismiss } from "./useDismiss";

describe("useDismiss", () => {
  it("starts closed and toggles via setOpen", () => {
    const { result } = renderHook(() => useDismiss<HTMLDivElement>());
    expect(result.current.open).toBe(false);
    act(() => { result.current.setOpen(true); });
    expect(result.current.open).toBe(true);
    act(() => { result.current.setOpen((v) => !v); });
    expect(result.current.open).toBe(false);
  });

  it("closes on an outside mousedown but stays open for a click inside the ref", () => {
    const { result } = renderHook(() => useDismiss<HTMLDivElement>());
    const inside = document.createElement("div");
    document.body.appendChild(inside);
    act(() => {
      result.current.ref.current = inside;
      result.current.setOpen(true);
    });
    // A mousedown inside the ref's element must not dismiss.
    act(() => { inside.dispatchEvent(new MouseEvent("mousedown", { bubbles: true })); });
    expect(result.current.open).toBe(true);
    // A mousedown outside dismisses.
    act(() => { document.body.dispatchEvent(new MouseEvent("mousedown", { bubbles: true })); });
    expect(result.current.open).toBe(false);
    inside.remove();
  });

  it("closes on Escape", () => {
    const { result } = renderHook(() => useDismiss<HTMLDivElement>());
    act(() => { result.current.setOpen(true); });
    act(() => { document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" })); });
    expect(result.current.open).toBe(false);
  });

  it("ignores outside clicks and Escape while closed (no listeners attached)", () => {
    const { result } = renderHook(() => useDismiss<HTMLDivElement>());
    act(() => { document.body.dispatchEvent(new MouseEvent("mousedown", { bubbles: true })); });
    act(() => { document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" })); });
    expect(result.current.open).toBe(false);
  });
});
