import { describe, it, expect, vi, afterEach } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import { useReauthRetry } from "./useReauthRetry";
import { ReauthRequiredError } from "../api";
import type { ReauthChallenge } from "../api";

// useReauthRetry wraps a destructive-action mutation. On ReauthRequiredError it opens a modal-state, awaits the operator's
// verdict (delivered via modal.resolve(true|false)), and either retries the original call or surfaces the original deny.
// These tests exercise the state-machine + single-flight + retry contract documented at the top of useReauthRetry.ts.
//
// Test idioms used throughout:
//   - act(async () => { x; await Promise.resolve(); }) — wraps state updates triggered by resolve() so React can flush
//     them inside the act() boundary. The `await Promise.resolve()` makes the arrow legitimately async (eslint
//     require-await) and lets the microtask queue drain so the hook's post-resolve setState calls land before the
//     assertions on result.current.* observe them.
//   - kickOff(...) helper — runs result.current.call(...) inside act, attaches a no-op .catch so vitest's
//     unhandled-rejection tracker stays quiet between kickoff and the eventual `expect(...).rejects` assert. Returns the
//     promise without a non-null assertion.

const fakeChallenge: ReauthChallenge = {
  authMethod: "local_password",
  reauthURL: "/api/auth/reauth",
};

function kickOff<R>(callFn: () => Promise<R>): Promise<R> {
  let p: Promise<R> = Promise.resolve(undefined as unknown as R); // sentinel; reassigned inside act
  act(() => {
    p = callFn();
    // Attach a no-op rejection handler so vitest's unhandled-rejection tracker stays quiet between kickoff and the
    // eventual `expect(promise).rejects.*` assert. The original promise's rejection state is unaffected.
    p.catch(() => {
      /* silenced; eventual assert will re-throw / verify */
    });
  });
  return p;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("useReauthRetry", () => {
  it("returns the wrapped result on success without opening the modal", async () => {
    // Explicit <[], string> on useReauthRetry so result.current.call() returns Promise<string> rather than Promise<unknown>;
    // without it, TypeScript can't narrow vi.fn().mockResolvedValue("ok") to a string-returning callable.
    const fn = vi.fn().mockResolvedValue("ok");
    const { result } = renderHook(() => useReauthRetry<[], string>(fn));

    // act(async () => ...) resolves to void; the async callback's return value is NOT propagated (Copilot #278). Capture
    // the call's resolved value INSIDE the act callback so the assertion below reads the real value, not undefined.
    let value: string | undefined;
    await act(async () => {
      value = await result.current.call();
    });
    expect(value).toBe("ok");
    expect(fn).toHaveBeenCalledTimes(1);
    expect(result.current.modal.open).toBe(false);
    expect(result.current.modal.challenge).toBeNull();
  });

  it("opens the modal and surfaces the challenge on ReauthRequiredError", async () => {
    const fn = vi.fn().mockRejectedValueOnce(new ReauthRequiredError(fakeChallenge));
    const { result } = renderHook(() => useReauthRetry(fn));

    const callPromise = kickOff<unknown>(() => result.current.call());
    await waitFor(() => { expect(result.current.modal.open).toBe(true); });
    expect(result.current.modal.challenge).toEqual(fakeChallenge);

    // Cancel so the dangling promise resolves; the retry-path test below covers the resolve(true) branch.
    await act(async () => {
      result.current.modal.resolve(false);
      await Promise.resolve();
    });
    await expect(callPromise).rejects.toBeInstanceOf(ReauthRequiredError);
  });

  it("retries fn once after a successful reauth verdict (operator confirms)", async () => {
    let attempts = 0;
    const fn = vi.fn(async (): Promise<string> => {
      // Trivial await keeps eslint's require-await happy without changing the implementation's effective behaviour;
      // the stub still throws/returns synchronously in the same microtask.
      await Promise.resolve();
      attempts += 1;
      if (attempts === 1) throw new ReauthRequiredError(fakeChallenge);
      return "after-reauth";
    });
    const { result } = renderHook(() => useReauthRetry(fn));

    const callPromise = kickOff<string>(() => result.current.call());
    await waitFor(() => { expect(result.current.modal.open).toBe(true); });

    await act(async () => {
      result.current.modal.resolve(true);
      await Promise.resolve();
    });
    const value = await callPromise;
    expect(value).toBe("after-reauth");
    expect(fn).toHaveBeenCalledTimes(2);
    // Modal closes after the verdict; challenge clears.
    await waitFor(() => { expect(result.current.modal.open).toBe(false); });
    expect(result.current.modal.challenge).toBeNull();
  });

  it("throws the original ReauthRequiredError when the operator cancels", async () => {
    const fn = vi.fn().mockRejectedValueOnce(new ReauthRequiredError(fakeChallenge));
    const { result } = renderHook(() => useReauthRetry(fn));

    const callPromise = kickOff<unknown>(() => result.current.call());
    await waitFor(() => { expect(result.current.modal.open).toBe(true); });

    await act(async () => {
      result.current.modal.resolve(false);
      await Promise.resolve();
    });
    await expect(callPromise).rejects.toBeInstanceOf(ReauthRequiredError);
    // fn was called once (the original); cancellation suppresses the retry.
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("collapses concurrent calls into one modal cycle (single-flight)", async () => {
    let attempts = 0;
    const fn = vi.fn(async (): Promise<string> => {
      // Trivial await keeps eslint's require-await happy without changing the implementation's effective behaviour;
      // the stub still throws/returns synchronously in the same microtask.
      await Promise.resolve();
      attempts += 1;
      // Every call throws ReauthRequiredError exactly once - the first time each call is invoked. Track per-call.
      if (attempts <= 2) throw new ReauthRequiredError(fakeChallenge);
      return `attempt-${String(attempts)}`;
    });
    const { result } = renderHook(() => useReauthRetry(fn));

    // Fire two concurrent calls before the modal verdict lands. Use the kickOff helper for both so unhandled-rejection
    // is silenced even though both ultimately resolve.
    const pA = kickOff<string>(() => result.current.call());
    const pB = kickOff<string>(() => result.current.call());
    await waitFor(() => { expect(result.current.modal.open).toBe(true); });

    // Modal opened ONCE despite two concurrent calls (single-flight contract). resolve once for both pending callers.
    await act(async () => {
      result.current.modal.resolve(true);
      await Promise.resolve();
    });

    const [vA, vB] = await Promise.all([pA, pB]);
    // Microtask order between pA's retry and pB's retry isn't guaranteed; the contract is that BOTH retries land and
    // observe distinct attempt counts. Sort so a future scheduler change doesn't flip [vA, vB] order and flake the test
    // (CodeRabbit #278).
    expect([vA, vB].slice().sort()).toEqual(["attempt-3", "attempt-4"]);
    // fn ran 4 times total: 2 initial deny + 2 retries.
    expect(fn).toHaveBeenCalledTimes(4);
  });

  it("propagates non-Reauth errors without opening the modal", async () => {
    const otherErr = new Error("server down");
    const fn = vi.fn().mockRejectedValue(otherErr);
    const { result } = renderHook(() => useReauthRetry(fn));

    // Capture the rejection inside act() so the assertion targets the call's promise, not the act-wrapper's void
    // promise (Copilot #278). Without this, the rejects.toBe assertion is fragile across testing-library versions.
    let caught: unknown;
    await act(async () => {
      try {
        await result.current.call();
      } catch (err) {
        caught = err;
      }
    });
    expect(caught).toBe(otherErr);
    expect(result.current.modal.open).toBe(false);
    expect(result.current.modal.challenge).toBeNull();
  });

  it("ignores a double-resolve call (defence against quick Confirm-then-Cancel)", async () => {
    let attempts = 0;
    const fn = vi.fn(async (): Promise<string> => {
      // Trivial await keeps eslint's require-await happy without changing the implementation's effective behaviour;
      // the stub still throws/returns synchronously in the same microtask.
      await Promise.resolve();
      attempts += 1;
      if (attempts === 1) throw new ReauthRequiredError(fakeChallenge);
      return "ok";
    });
    const { result } = renderHook(() => useReauthRetry(fn));

    const callPromise = kickOff<string>(() => result.current.call());
    await waitFor(() => { expect(result.current.modal.open).toBe(true); });

    // First resolve(true) wins; the second resolve(false) is a no-op because resolverRef has been cleared.
    await act(async () => {
      result.current.modal.resolve(true);
      result.current.modal.resolve(false);
      await Promise.resolve();
    });
    await expect(callPromise).resolves.toBe("ok");
  });

  it("forwards the same args to the retry call", async () => {
    let attempts = 0;
    const fn = vi.fn(async (a: string, b: number): Promise<string> => {
      // See note on the sibling test about the trivial await + eslint require-await.
      await Promise.resolve();
      attempts += 1;
      if (attempts === 1) throw new ReauthRequiredError(fakeChallenge);
      return `${a}-${String(b)}-attempt-${String(attempts)}`;
    });
    const { result } = renderHook(() => useReauthRetry(fn));

    const callPromise = kickOff<string>(() => result.current.call("hello", 42));
    await waitFor(() => { expect(result.current.modal.open).toBe(true); });
    await act(async () => {
      result.current.modal.resolve(true);
      await Promise.resolve();
    });
    await expect(callPromise).resolves.toBe("hello-42-attempt-2");
    // Both invocations saw the same args.
    expect(fn.mock.calls[0]).toEqual(["hello", 42]);
    expect(fn.mock.calls[1]).toEqual(["hello", 42]);
  });
});
