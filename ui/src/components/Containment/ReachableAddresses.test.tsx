import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { ReachableAddresses } from "./ReachableAddresses";
import { PermissionsProvider } from "../../permissions";
import { PermissionAction } from "../../permissions-core";
import * as api from "../../api";
import type { ContainmentState, ReachableAddress, ReachableSet } from "../../types";

const makeSet = (over: Partial<ReachableSet> = {}): ReachableSet => ({
  version: 4,
  addresses: [
    { cidr: "198.51.100.7/32", port: 443, transport: "tcp", note: "MDM server" },
    { cidr: "203.0.113.0/24" },
  ],
  updated_at: "2026-09-18T12:00:00Z",
  updated_by: "usr_1",
  updated_by_label: "alice@example.com",
  ...over,
});

// A containment row as GET /api/containment returns it. contained + a completed current delivery is the "contained" phase;
// contained with nothing delivered yet is "containing", and a released host has contained false.
const makeState = (over: Partial<ContainmentState> = {}): ContainmentState =>
  ({
    host_id: "h1",
    version: 3,
    contained: true,
    delivery: { current: true, status: "completed" },
    ...over,
  }) as ContainmentState;

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

async function renderLoaded(
  set: ReachableSet = makeSet(),
  states: ContainmentState[] | Error = [makeState()],
  permissions: string[] = [PermissionAction.ContainmentConfigRead, PermissionAction.ContainmentConfigWrite],
) {
  vi.spyOn(api, "getReachableAddresses").mockResolvedValue(set);
  const list = vi.spyOn(api, "listContainment");
  if (states instanceof Error) {
    list.mockRejectedValue(states);
  } else {
    list.mockResolvedValue(states);
  }
  render(
    <PermissionsProvider permissions={permissions}>
      <ReachableAddresses />
    </PermissionsProvider>,
  );
  await screen.findByText(/destinations\./);
}

function rows(): (string | null)[] {
  return screen
    .queryAllByRole("row")
    .slice(1)
    .map((r) => r.textContent);
}

function addDestination(cidr: string, port = "", transport = "", note = "") {
  fireEvent.change(screen.getByLabelText("Destination"), { target: { value: cidr } });
  fireEvent.change(screen.getByLabelText("Port"), { target: { value: port } });
  fireEvent.change(screen.getByLabelText("Transport"), { target: { value: transport } });
  fireEvent.change(screen.getByLabelText("Name"), { target: { value: note } });
  fireEvent.click(screen.getByRole("button", { name: "Add destination" }));
}

async function saveWithReason(reason: string) {
  fireEvent.click(screen.getByRole("button", { name: "Save and push to hosts" }));
  fireEvent.change(await screen.findByLabelText(/required for audit log/i), { target: { value: reason } });
  fireEvent.click(screen.getByRole("button", { name: "Save" }));
}

describe("ReachableAddresses", () => {
  // spec:web-ui/reachable-destinations-are-edited-in-containment-settings/the-console-shows-the-destinations-and-who-they-reach
  it("shows the set, what each destination allows, the bound, the last change and how many hosts it reaches", async () => {
    await renderLoaded(makeSet(), [
      makeState({ host_id: "h1" }),
      // On its way: contained, with no delivery confirmed. It is still a host this set reaches.
      makeState({ host_id: "h2", delivery: undefined }),
      // Released: the set does not reach it, so it must not be counted.
      makeState({ host_id: "h3", contained: false }),
    ]);

    expect(rows()).toEqual([
      expect.stringContaining("198.51.100.7/32Port 443, TCPMDM server"),
      expect.stringContaining("203.0.113.0/24Any port, TCP and UDP"),
    ]);
    expect(screen.getByText(/2 of 64 destinations\. Last saved .* by alice@example\.com\./)).toBeVisible();
    expect(screen.getByText("2 hosts are contained or being contained right now.")).toBeVisible();
    expect(screen.getByRole("button", { name: "Save and push to hosts" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Discard changes" })).toBeDisabled();
  });

  it("says no destinations are added and omits the last change for the set no operator has changed", async () => {
    await renderLoaded(makeSet({ version: 0, addresses: [], updated_at: undefined, updated_by: undefined }), []);

    expect(screen.getByText("No destinations added. A contained host reaches only the EDR server.")).toBeVisible();
    expect(screen.getByText("0 of 64 destinations.")).toBeVisible();
    expect(screen.getByText("0 hosts are contained or being contained right now.")).toBeVisible();
  });

  it("names who last saved the set", async () => {
    await renderLoaded();

    expect(screen.getByText(/Last saved .* by alice@example\.com\./)).toBeVisible();
  });

  // A deleted user or service account: the server resolves no label, and the raw principal id beats saying nothing about who
  // widened what every contained host can reach.
  it("falls back to the principal id when the label could not be resolved", async () => {
    await renderLoaded(makeSet({ updated_by_label: undefined }));

    expect(screen.getByText(/Last saved .* by usr_1\./)).toBeVisible();
  });

  it("counts one contained host in the singular", async () => {
    await renderLoaded(makeSet(), [makeState()]);

    expect(screen.getByText("1 host is contained or being contained right now.")).toBeVisible();
  });

  // spec:web-ui/reachable-destinations-are-edited-in-containment-settings/a-count-that-cannot-be-read-is-not-reported-as-a-number
  it("says the count could not be read rather than reporting a number, and stays editable", async () => {
    await renderLoaded(makeSet(), new Error("containment unavailable"));

    expect(await screen.findByText("How many hosts this reaches could not be read.")).toBeVisible();
    expect(screen.queryByText(/hosts are contained/)).toBeNull();
    expect(rows()).toHaveLength(2);
    expect(screen.getByRole("button", { name: "Add destination" })).toBeVisible();
  });

  // spec:web-ui/reachable-destinations-are-edited-in-containment-settings/a-reader-cannot-change-the-destinations
  it("offers no editing to an operator without write permission", async () => {
    await renderLoaded(makeSet(), [makeState()], [PermissionAction.ContainmentConfigRead]);

    expect(rows()).toHaveLength(2);
    expect(screen.getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Destination", "Allows", "Name"]);
    expect(screen.queryByRole("button", { name: /Remove/ })).toBeNull();
    expect(screen.queryByLabelText("Destination")).toBeNull();
    expect(screen.queryByRole("button", { name: "Save and push to hosts" })).toBeNull();
  });

  // spec:web-ui/reachable-destinations-are-edited-in-containment-settings/an-operator-saves-changed-destinations-with-a-reason
  it("saves the edited set with the reason and the version it started from", async () => {
    await renderLoaded();
    const saved: ReachableAddress[] = [
      { cidr: "203.0.113.0/24" },
      { cidr: "192.0.2.10/32", port: 8443, transport: "tcp", note: "Forensic share" },
    ];
    const replace = vi.spyOn(api, "replaceReachableAddresses").mockResolvedValue(makeSet({ version: 5, addresses: saved }));

    fireEvent.click(screen.getByRole("button", { name: "Remove 198.51.100.7/32" }));
    addDestination("192.0.2.10/32", "8443", "tcp", "Forensic share");
    expect(screen.getByLabelText("Destination")).toHaveValue("");
    expect(replace).not.toHaveBeenCalled();

    await saveWithReason("keep the forensic share reachable");

    await waitFor(() => {
      expect(replace).toHaveBeenCalledWith(saved, "keep the forensic share reachable", 4);
    });
    expect(await screen.findByText(/Saved as version 5\./)).toBeVisible();
    expect(screen.getByText(/a host already contained gets it within minutes/)).toBeVisible();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("button", { name: "Save and push to hosts" })).toBeDisabled();
  });

  it("sends nothing until the reason is given, and nothing at all when the reason modal is cancelled", async () => {
    await renderLoaded();
    const replace = vi.spyOn(api, "replaceReachableAddresses");

    fireEvent.click(screen.getByRole("button", { name: "Remove 203.0.113.0/24" }));
    fireEvent.click(screen.getByRole("button", { name: "Save and push to hosts" }));
    await screen.findByLabelText(/required for audit log/i);
    expect(replace).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    expect(replace).not.toHaveBeenCalled();
    expect(rows()).toHaveLength(1);
  });

  // spec:web-ui/reachable-destinations-are-edited-in-containment-settings/a-refused-destination-is-shown-and-the-draft-kept
  it("shows the server's refusal, keeps the draft, and clears the message on the next edit", async () => {
    await renderLoaded();
    vi.spyOn(api, "replaceReachableAddresses").mockRejectedValue(
      new Error("That range is too broad to keep containment meaningful. reachable set: address range is too broad: 10.0.0.0/4"),
    );

    addDestination("10.0.0.0/4");
    await saveWithReason("widen to the corporate range");

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("That range is too broad to keep containment meaningful.");
    expect(alert).toHaveTextContent("10.0.0.0/4");
    // The reason dialog is gone: the refusal names the entry to fix, and the list to fix it in is behind the dialog.
    expect(screen.queryByRole("dialog")).toBeNull();
    // The draft is kept exactly as the operator built it, so the entry can be fixed rather than retyped.
    expect(rows()).toHaveLength(3);

    fireEvent.click(screen.getByRole("button", { name: "Remove 10.0.0.0/4" }));

    expect(screen.queryByRole("alert")).toBeNull();
  });

  // spec:web-ui/reachable-destinations-are-edited-in-containment-settings/a-save-of-an-outdated-set-is-refused
  it("keeps the draft when the set changed since it loaded, and loads the latest on request", async () => {
    await renderLoaded();
    vi.spyOn(api, "replaceReachableAddresses").mockRejectedValue(
      new api.ReachableSetConflictError("Someone else changed these destinations after this page loaded them."),
    );

    fireEvent.click(screen.getByRole("button", { name: "Remove 203.0.113.0/24" }));
    await saveWithReason("no longer needed");

    expect(await screen.findByRole("alert")).toHaveTextContent("Someone else changed these destinations after this page loaded them.");
    // The recovery is on the page, so the dialog must not be covering it.
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(rows()).toHaveLength(1);

    // The other operator's set, at the version they saved.
    const theirs = makeSet({ version: 9, addresses: [{ cidr: "192.0.2.99/32", note: "Their VPN" }] });
    vi.spyOn(api, "getReachableAddresses").mockResolvedValue(theirs);
    fireEvent.click(screen.getByRole("button", { name: /Load the latest destinations/ }));

    await waitFor(() => {
      expect(rows()).toEqual([expect.stringContaining("192.0.2.99/32Any port, TCP and UDPTheir VPN")]);
    });
    expect(screen.queryByRole("alert")).toBeNull();

    // A save from here names the version that was loaded, not the one the page opened at.
    const replace = vi.spyOn(api, "replaceReachableAddresses").mockResolvedValue(makeSet({ version: 10, addresses: [] }));
    fireEvent.click(screen.getByRole("button", { name: "Remove 192.0.2.99/32" }));
    await saveWithReason("their VPN is gone");
    await waitFor(() => {
      expect(replace).toHaveBeenCalledWith([], "their VPN is gone", 9);
    });
  });

  it("will not add a destination the draft already holds, an empty one, or a port that is not a port", async () => {
    await renderLoaded();
    const add = () => screen.getByRole("button", { name: "Add destination" });

    expect(add()).toBeDisabled();

    // Already in the draft, as written: same address, port and transport, which is what the server calls a duplicate.
    addDestination("198.51.100.7/32", "443", "tcp", "A second name");
    expect(add()).toBeDisabled();
    expect(rows()).toHaveLength(2);

    // The same address narrowed differently is a different destination, so it is offered.
    fireEvent.change(screen.getByLabelText("Port"), { target: { value: "8443" } });
    expect(add()).toBeEnabled();

    fireEvent.change(screen.getByLabelText("Port"), { target: { value: "70000" } });
    expect(add()).toBeDisabled();
    expect(screen.getByRole("alert")).toHaveTextContent("A port must be a number between 1 and 65535");

    fireEvent.change(screen.getByLabelText("Port"), { target: { value: "https" } });
    expect(add()).toBeDisabled();

    // A number in range but not a whole one is still not a port. Number("443.5") passes a bounds check on its own.
    fireEvent.change(screen.getByLabelText("Port"), { target: { value: "443.5" } });
    expect(add()).toBeDisabled();

    // An empty port is every port, which is allowed.
    fireEvent.change(screen.getByLabelText("Port"), { target: { value: "" } });
    expect(add()).toBeEnabled();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("discards a draft back to the stored set", async () => {
    await renderLoaded();

    fireEvent.click(screen.getByRole("button", { name: "Remove 198.51.100.7/32" }));
    addDestination("192.0.2.10/32");
    expect(rows()).toHaveLength(2);

    fireEvent.click(screen.getByRole("button", { name: "Discard changes" }));

    expect(rows()).toEqual([
      expect.stringContaining("198.51.100.7/32Port 443, TCPMDM server"),
      expect.stringContaining("203.0.113.0/24Any port, TCP and UDP"),
    ]);
    expect(screen.getByRole("button", { name: "Discard changes" })).toBeDisabled();
  });

  it("reports a set that could not be loaded", async () => {
    vi.spyOn(api, "getReachableAddresses").mockRejectedValue(new Error("service unavailable"));
    vi.spyOn(api, "listContainment").mockResolvedValue([]);
    render(
      <PermissionsProvider permissions={[PermissionAction.ContainmentConfigRead]}>
        <ReachableAddresses />
      </PermissionsProvider>,
    );

    expect(await screen.findByText(/Reachable destinations could not be loaded: service unavailable/)).toBeVisible();
  });
});
