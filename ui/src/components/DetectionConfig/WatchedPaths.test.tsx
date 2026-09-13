import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { WatchedPaths } from "./WatchedPaths";
import * as api from "../../api";
import type { ReplaceWatchedPathsResult, WatchedPath, WatchedPaths as WatchedPathsResponse } from "../../api";

const BUILT_IN: WatchedPath[] = [
  { path: "/etc/sudoers", match: "literal" },
  { path: "/etc/sudoers.d/", match: "prefix" },
];

const makeSet = (over: Partial<WatchedPathsResponse> = {}): WatchedPathsResponse => ({
  version: 2,
  paths: [
    { path: "/Library/StartupItems/", match: "prefix" },
    { path: "/Users/alice/.ssh/authorized_keys", match: "literal" },
  ],
  updated_at: "2026-09-13T12:00:00Z",
  updated_by: "usr_1",
  updated_by_label: "alice@example.com",
  built_in: BUILT_IN,
  max_paths: 32,
  ...over,
});

const makeResult = (paths: WatchedPath[], over: Partial<ReplaceWatchedPathsResult> = {}): ReplaceWatchedPathsResult => ({
  set: { version: 3, paths, updated_at: "2026-09-13T12:05:00Z", updated_by: "usr_2", updated_by_label: "bob@example.com" },
  fanout_hosts: 3,
  fanout_failed: 0,
  ...over,
});

// jsdom doesn't implement HTMLDialogElement.showModal/close; stub them so the reason modal renders.
beforeEach(() => {
  HTMLDialogElement.prototype.showModal = function showModal() {
    this.open = true;
  };
  HTMLDialogElement.prototype.close = function close() {
    this.open = false;
  };
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function renderLoaded(set: WatchedPathsResponse = makeSet(), canWrite = true) {
  vi.spyOn(api, "getWatchedPaths").mockResolvedValue(set);
  render(<WatchedPaths canWrite={canWrite} />);
  await screen.findByText(/paths\./);
}

function rows(): string[] {
  return screen
    .queryAllByRole("row")
    .slice(1)
    .map((r) => r.textContent);
}

function addPath(path: string, match: WatchedPath["match"]) {
  fireEvent.change(screen.getByLabelText("Path"), { target: { value: path } });
  fireEvent.change(screen.getByLabelText("Covers"), { target: { value: match } });
  fireEvent.click(screen.getByRole("button", { name: "Add path" }));
}

async function saveWithReason(reason: string) {
  fireEvent.click(screen.getByRole("button", { name: "Save and push to hosts" }));
  fireEvent.change(await screen.findByLabelText(/required for audit log/i), { target: { value: reason } });
  fireEvent.click(screen.getByRole("button", { name: "Save" }));
}

describe("WatchedPaths", () => {
  // spec:web-ui/watched-file-paths-are-edited-in-detection-tuning/the-console-shows-the-set-and-what-is-always-watched
  it("shows the stored set, the always-watched paths, the bound and the last change", async () => {
    await renderLoaded();

    expect(rows()).toEqual([
      expect.stringContaining("/Library/StartupItems/Everything under it"),
      expect.stringContaining("/Users/alice/.ssh/authorized_keysThis file"),
    ]);
    expect(screen.getByText(/on top of the ones it always watches: \/etc\/sudoers, \/etc\/sudoers\.d\//)).toBeVisible();
    expect(screen.getByText(/2 of 32 paths\. Last saved .* by alice@example\.com\./)).toBeVisible();
    expect(screen.getByRole("button", { name: "Save and push to hosts" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Discard changes" })).toBeDisabled();
  });

  it("says no paths are added and omits the last change for the set no operator has changed", async () => {
    await renderLoaded(makeSet({ version: 0, paths: [], updated_at: undefined, updated_by: undefined }));

    expect(screen.getByText("No paths added. Hosts watch only the paths they always watch.")).toBeVisible();
    expect(screen.getByText("0 of 32 paths.")).toBeVisible();
  });

  // spec:web-ui/watched-file-paths-are-edited-in-detection-tuning/a-reader-cannot-change-the-set
  it("offers no editing to an operator without write permission", async () => {
    await renderLoaded(makeSet(), false);

    expect(rows()).toHaveLength(2);
    expect(screen.getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Path", "Covers"]);
    expect(screen.queryByRole("button", { name: /Remove/ })).toBeNull();
    expect(screen.queryByLabelText("Path")).toBeNull();
    expect(screen.queryByRole("button", { name: "Save and push to hosts" })).toBeNull();
  });

  // spec:web-ui/watched-file-paths-are-edited-in-detection-tuning/an-operator-saves-a-changed-set-with-a-reason
  it("saves the edited set with the reason and reports how many hosts it was queued for", async () => {
    await renderLoaded();
    const saved: WatchedPath[] = [
      { path: "/Users/alice/.ssh/authorized_keys", match: "literal" },
      { path: "/Library/Security/SecurityAgentPlugins/", match: "prefix" },
    ];
    const replace = vi.spyOn(api, "replaceWatchedPaths").mockResolvedValue(makeResult(saved, { fanout_hosts: 3, fanout_failed: 1 }));

    fireEvent.click(screen.getByRole("button", { name: "Remove /Library/StartupItems/" }));
    addPath("/Library/Security/SecurityAgentPlugins/", "prefix");
    expect(screen.getByLabelText("Path")).toHaveValue("");
    expect(screen.getByText("2 of 32 paths. Last saved", { exact: false })).toBeVisible();
    expect(replace).not.toHaveBeenCalled();

    await saveWithReason("watch authorization plugins");

    await waitFor(() => {
      expect(replace).toHaveBeenCalledWith(saved, "watch authorization plugins", 2);
    });
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Saved as version 3. Queued for 2 of 3 enrolled hosts; the rest receive it within minutes.",
    );
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("button", { name: "Save and push to hosts" })).toBeDisabled();
    expect(screen.getByText(/Last saved .* by bob@example\.com\./)).toBeVisible();
  });

  it("reports a push that reached every host, in the singular for one host", async () => {
    await renderLoaded();
    const saved: WatchedPath[] = [{ path: "/Library/StartupItems/", match: "prefix" }];
    vi.spyOn(api, "replaceWatchedPaths").mockResolvedValue(makeResult(saved, { fanout_hosts: 1 }));

    fireEvent.click(screen.getByRole("button", { name: "Remove /Users/alice/.ssh/authorized_keys" }));
    await saveWithReason("key no longer used");

    expect(await screen.findByRole("status")).toHaveTextContent("Saved as version 3. Queued for 1 of 1 enrolled host.");
  });

  it("names the saver by principal id when the server could not resolve a label, not by the previous saver's name", async () => {
    await renderLoaded();
    const saved: WatchedPath[] = [{ path: "/Library/StartupItems/", match: "prefix" }];
    vi.spyOn(api, "replaceWatchedPaths").mockResolvedValue({
      set: { version: 3, paths: saved, updated_at: "2026-09-13T12:05:00Z", updated_by: "svc_4" },
      fanout_hosts: 1,
      fanout_failed: 0,
    });

    fireEvent.click(screen.getByRole("button", { name: "Remove /Users/alice/.ssh/authorized_keys" }));
    await saveWithReason("key no longer used");

    expect(await screen.findByText(/Last saved .* by svc_4\./)).toBeVisible();
  });

  // spec:web-ui/watched-file-paths-are-edited-in-detection-tuning/a-push-that-reached-no-host-is-called-out
  it("calls out a saved set the server could not push because it could not list hosts", async () => {
    await renderLoaded();
    vi.spyOn(api, "replaceWatchedPaths").mockResolvedValue(makeResult([], { fanout_hosts: 0, fanout_skipped_reason: "host_lister_error" }));

    fireEvent.click(screen.getByRole("button", { name: "Remove /Library/StartupItems/" }));
    fireEvent.click(screen.getByRole("button", { name: "Remove /Users/alice/.ssh/authorized_keys" }));
    await saveWithReason("clear the set");

    expect(await screen.findByRole("alert")).toHaveTextContent("Saved as version 3, but not sent: the enrolled hosts could not be listed.");
    expect(screen.queryByRole("status")).toBeNull();
  });

  // spec:web-ui/watched-file-paths-are-edited-in-detection-tuning/a-refused-set-is-shown-and-the-draft-kept
  it("shows the server's refusal as written and keeps the draft for fixing", async () => {
    await renderLoaded();
    vi.spyOn(api, "replaceWatchedPaths").mockRejectedValue(
      new api.DetectionConfigApiError("invalid_input", 'invalid watched paths: entry 2 ("/Users/"): the prefix is too broad', 400),
    );

    addPath("/Users/", "prefix");
    await saveWithReason("everything");

    expect(await screen.findByRole("alert")).toHaveTextContent(
      'Not saved: invalid watched paths: entry 2 ("/Users/"): the prefix is too broad',
    );
    expect(rows()).toHaveLength(3);
    expect(screen.getByRole("button", { name: "Save and push to hosts" })).toBeEnabled();
    expect(screen.queryByRole("dialog")).toBeNull();

    // Editing the draft again clears the stale refusal.
    fireEvent.click(screen.getByRole("button", { name: "Remove /Users/" }));
    expect(screen.queryByRole("alert")).toBeNull();
  });

  // spec:web-ui/watched-file-paths-are-edited-in-detection-tuning/a-save-of-an-outdated-set-is-refused
  it("refuses a save made after someone else changed the set, keeps the draft, and loads the latest set on request", async () => {
    await renderLoaded();
    vi.spyOn(api, "replaceWatchedPaths").mockRejectedValue(
      new api.DetectionConfigApiError("detection_config.conflict", "the watched paths were changed since they were read", 409),
    );
    const latest = makeSet({ version: 3, paths: [{ path: "/etc/emond.d/", match: "prefix" }], updated_by_label: "bob@example.com" });
    // The same spy the initial load went through, so its count is reset to count only the reload.
    const load = vi.spyOn(api, "getWatchedPaths").mockResolvedValue(latest);
    load.mockClear();

    addPath("/Library/Extra/", "prefix");
    await saveWithReason("stale edit");

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Not saved: someone changed the watched paths after this page loaded them. Load the latest set to see their change",
    );
    expect(rows()).toHaveLength(3);

    fireEvent.click(screen.getByRole("button", { name: "Load the latest set (discards your changes)" }));

    await waitFor(() => {
      expect(rows()).toEqual([expect.stringContaining("/etc/emond.d/")]);
    });
    expect(load).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.getByText(/1 of 32 paths\. Last saved .* by bob@example\.com\./)).toBeVisible();
    expect(screen.getByRole("button", { name: "Save and push to hosts" })).toBeDisabled();
  });

  it("says so when the latest set cannot be loaded after a refused save", async () => {
    await renderLoaded();
    vi.spyOn(api, "replaceWatchedPaths").mockRejectedValue(new api.DetectionConfigApiError("detection_config.conflict", "changed", 409));
    vi.spyOn(api, "getWatchedPaths").mockRejectedValue(new Error("network down"));

    addPath("/Library/Extra/", "prefix");
    await saveWithReason("stale edit");
    fireEvent.click(await screen.findByRole("button", { name: "Load the latest set (discards your changes)" }));

    expect(await screen.findByText("The latest set could not be loaded: network down")).toBeVisible();
    expect(rows()).toHaveLength(3);
  });

  it("clears a failed save's message when a retry of the same draft succeeds", async () => {
    await renderLoaded();
    const saved: WatchedPath[] = [...makeSet().paths, { path: "/Library/Extra/", match: "prefix" }];
    vi.spyOn(api, "replaceWatchedPaths")
      .mockRejectedValueOnce(new Error("503 service unavailable"))
      .mockResolvedValueOnce(makeResult(saved));

    addPath("/Library/Extra/", "prefix");
    await saveWithReason("first try");
    expect(await screen.findByRole("alert")).toHaveTextContent("Not saved: 503 service unavailable");

    await saveWithReason("second try");

    expect(await screen.findByRole("status")).toHaveTextContent("Saved as version 3.");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("adds a path exactly as typed, since a path may contain spaces", async () => {
    await renderLoaded(makeSet({ paths: [] }));
    const replace = vi.spyOn(api, "replaceWatchedPaths").mockResolvedValue(makeResult([]));

    addPath("/Users/Shared/report ", "literal");
    await saveWithReason("canary");

    await waitFor(() => {
      expect(replace).toHaveBeenCalledWith([{ path: "/Users/Shared/report ", match: "literal" }], "canary", 2);
    });
  });

  it("sends nothing when the reason prompt is cancelled", async () => {
    await renderLoaded();
    const replace = vi.spyOn(api, "replaceWatchedPaths");

    addPath("/Library/StartupItems/extra", "literal");
    fireEvent.click(screen.getByRole("button", { name: "Save and push to hosts" }));
    fireEvent.click(await screen.findByRole("button", { name: "Cancel" }));

    expect(screen.queryByRole("dialog")).toBeNull();
    expect(replace).not.toHaveBeenCalled();
    expect(rows()).toHaveLength(3);
  });

  it("discards the draft back to the stored set", async () => {
    await renderLoaded();

    fireEvent.click(screen.getByRole("button", { name: "Remove /Library/StartupItems/" }));
    addPath("/Library/Extra/", "prefix");
    expect(rows()).toEqual([expect.stringContaining("/Users/alice"), expect.stringContaining("/Library/Extra/")]);

    fireEvent.click(screen.getByRole("button", { name: "Discard changes" }));

    expect(rows()).toEqual([expect.stringContaining("/Library/StartupItems/"), expect.stringContaining("/Users/alice")]);
    expect(screen.getByRole("button", { name: "Save and push to hosts" })).toBeDisabled();
  });

  it("treats a reordered draft holding the same entries as changed, since the set is sent in order", async () => {
    await renderLoaded();

    fireEvent.click(screen.getByRole("button", { name: "Remove /Library/StartupItems/" }));
    addPath("/Library/StartupItems/", "prefix");

    expect(screen.getByRole("button", { name: "Save and push to hosts" })).toBeEnabled();
  });

  it("refuses to add an empty path, an entry already in the draft, or a path past the bound", async () => {
    await renderLoaded(makeSet({ max_paths: 3 }));
    const add = () => screen.getByRole("button", { name: "Add path" });

    expect(add()).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Path"), { target: { value: "   " } });
    expect(add()).toBeDisabled();

    // The same path with the other match is a different entry.
    fireEvent.change(screen.getByLabelText("Path"), { target: { value: "/Library/StartupItems/" } });
    fireEvent.change(screen.getByLabelText("Covers"), { target: { value: "prefix" } });
    expect(add()).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Covers"), { target: { value: "literal" } });
    expect(add()).toBeEnabled();

    addPath("/Library/Third/", "prefix");
    expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(4);
    fireEvent.change(screen.getByLabelText("Path"), { target: { value: "/Library/Fourth/" } });
    expect(add()).toBeDisabled();
  });

  it("disables editing while a save is in flight", async () => {
    await renderLoaded();
    let settle: (r: ReplaceWatchedPathsResult) => void = () => undefined;
    vi.spyOn(api, "replaceWatchedPaths").mockReturnValue(
      new Promise((resolve) => {
        settle = resolve;
      }),
    );

    addPath("/Library/Extra/", "prefix");
    await saveWithReason("slow network");

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Remove /Library/Extra/" })).toBeDisabled();
    });
    expect(screen.getByRole("button", { name: "Discard changes" })).toBeDisabled();
    expect(screen.getByLabelText("Path")).toBeDisabled();
    expect(screen.getByLabelText("Covers")).toBeDisabled();
    settle(makeResult(makeSet().paths));
    expect(await screen.findByRole("status")).toBeVisible();
  });

  it("says the set could not be loaded", async () => {
    vi.spyOn(api, "getWatchedPaths").mockRejectedValue(new Error("403 forbidden"));
    render(<WatchedPaths canWrite />);

    expect(await screen.findByText("Watched paths could not be loaded: 403 forbidden")).toBeVisible();
  });
});
