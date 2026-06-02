import { describe, it, expect, vi } from "vitest";

import { createDedupedRunner } from "./dedupe";

// deferred returns a promise plus its resolver so a test can hold a "run" open and
// observe that concurrent invocations collapse to one.
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => { resolve = r; });
  return { promise, resolve };
}

describe("createDedupedRunner", () => {
  // tick yields a couple of microtasks so the deferred task invocation (the runner schedules task()
  // via Promise.resolve().then(...)) and its finally have a chance to run before we assert.
  const tick = async () => { await Promise.resolve(); await Promise.resolve(); };

  // flush waits a macrotask, which drains the entire microtask chain (then -> catch -> finally)
  // regardless of its length, so inFlight is guaranteed reset before the next run().
  const flush = () => new Promise<void>((r) => { setTimeout(r, 0); });

  // spec:web-ui/authorization-denials-degrade-gracefully/simultaneous-denials-collapse-to-one-refetch
  it("collapses concurrent invocations to a single in-flight run", async () => {
    const d = deferred();
    const task = vi.fn(() => d.promise);
    const run = createDedupedRunner(task);

    run();
    run();
    run();
    await tick();

    // The dedup guard is set synchronously on the first call, so the 2nd and 3rd calls are dropped
    // before they queue a task; only one invocation reaches task().
    expect(task).toHaveBeenCalledTimes(1);
  });

  it("allows a new run once the previous one settles", async () => {
    const first = deferred();
    const second = deferred();
    const task = vi.fn().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    const run = createDedupedRunner(task);

    run();
    await tick();
    expect(task).toHaveBeenCalledTimes(1);

    // A call mid-flight is dropped (first.promise is still pending).
    run();
    await tick();
    expect(task).toHaveBeenCalledTimes(1);

    // Settle the first run; the in-flight window closes.
    first.resolve();
    await tick();

    run();
    await tick();
    expect(task).toHaveBeenCalledTimes(2);
    second.resolve();
  });

  it("reopens the window when the task throws synchronously", async () => {
    const task = vi
      .fn<() => Promise<void>>()
      .mockImplementationOnce(() => { throw new Error("sync boom"); })
      .mockResolvedValueOnce(undefined);
    const run = createDedupedRunner(task);

    run();
    await flush(); // drains the throw -> catch -> finally chain so inFlight is reset
    run();
    await flush();
    expect(task).toHaveBeenCalledTimes(2);
  });

  it("reopens the window even when the task rejects", async () => {
    const task = vi
      .fn()
      .mockRejectedValueOnce(new Error("boom"))
      .mockResolvedValueOnce(undefined);
    const run = createDedupedRunner(task);

    run();
    await flush(); // drains the reject -> catch -> finally chain so inFlight is reset
    run();
    await flush();
    expect(task).toHaveBeenCalledTimes(2);
  });
});
