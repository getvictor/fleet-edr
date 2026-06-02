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
  // spec:web-ui/authorization-denials-degrade-gracefully/simultaneous-denials-collapse-to-one-refetch
  it("collapses concurrent invocations to a single in-flight run", () => {
    const d = deferred();
    const task = vi.fn(() => d.promise);
    const run = createDedupedRunner(task);

    run();
    run();
    run();

    expect(task).toHaveBeenCalledTimes(1);
  });

  it("allows a new run once the previous one settles", async () => {
    const first = deferred();
    const second = deferred();
    const task = vi.fn().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    const run = createDedupedRunner(task);

    run();
    expect(task).toHaveBeenCalledTimes(1);

    // A call mid-flight is dropped.
    run();
    expect(task).toHaveBeenCalledTimes(1);

    // Settle the first run; the in-flight window closes.
    first.resolve();
    await Promise.resolve();
    await Promise.resolve();

    run();
    expect(task).toHaveBeenCalledTimes(2);
    second.resolve();
  });

  it("reopens the window even when the task rejects", async () => {
    const task = vi
      .fn()
      .mockRejectedValueOnce(new Error("boom"))
      .mockResolvedValueOnce(undefined);
    const run = createDedupedRunner(task);

    run();
    // Let the rejected promise settle through the .catch().finally() chain.
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();

    run();
    expect(task).toHaveBeenCalledTimes(2);
  });
});
