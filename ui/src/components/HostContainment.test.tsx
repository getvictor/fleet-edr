import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import * as api from "../api";
import { PermissionsProvider } from "../permissions";
import type { ContainmentState, HostHealth } from "../types";
import { HostContainment } from "./HostContainment";

const HOST = "93DFC6F5-763D-5075-B305-8AC145D12F96";

const never: ContainmentState = { host_id: HOST, contained: false, version: 0, epoch: 0 };
const contained: ContainmentState = {
  host_id: HOST, contained: true, version: 1, epoch: 100, reason: "beaconing",
  delivery: { command_id: 7, status: "completed", current: true },
};

function renderControl(permissions: readonly string[] = ["host.read", "host.isolate"], health: HostHealth | null = null) {
  return render(
    <PermissionsProvider permissions={permissions}>
      <HostContainment hostId={HOST} health={health} />
    </PermissionsProvider>,
  );
}

// healthWith builds a host-health snapshot carrying the agent-reported conditions these tests read.
function healthWith(components: HostHealth["components"]): HostHealth {
  return { overall_status: "healthy", reported_at_ns: 1, components, derived_components: null, episodes: [] };
}

// lastButton is the dialog's confirm button: it carries the same label as the header action that opened the dialog, and comes after it.
function lastButton(name: string): HTMLElement {
  const buttons = screen.getAllByRole("button", { name });
  return buttons[buttons.length - 1];
}

// jsdom has no dialog methods; these stand-ins are restored after each test so they do not leak into other files' tests.
const originalShowModal = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, "showModal");
const originalClose = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, "close");

function restore(name: "showModal" | "close", descriptor: PropertyDescriptor | undefined) {
  if (descriptor) {
    Object.defineProperty(HTMLDialogElement.prototype, name, descriptor);
  } else {
    Reflect.deleteProperty(HTMLDialogElement.prototype, name);
  }
}

beforeEach(() => {
  HTMLDialogElement.prototype.showModal = function showModal() {
    this.open = true;
  };
  HTMLDialogElement.prototype.close = function close() {
    this.open = false;
  };
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  restore("showModal", originalShowModal);
  restore("close", originalClose);
});

const pendingContain: ContainmentState = {
  host_id: HOST, contained: true, version: 1, epoch: 100, reason: "beaconing",
  delivery: { command_id: 7, status: "pending", current: true },
};

describe("HostContainment", () => {
  it("offers Contain to an operator holding host.isolate on a host that is not contained, with no badge and no polling", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const read = vi.spyOn(api, "getHostContainment").mockResolvedValue(never);
    renderControl();
    expect(await screen.findByRole("button", { name: "Contain host" })).toBeVisible();
    expect(screen.queryByText(/Contain(ed|ing)/)).toBeNull();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(9000);
    });
    expect(read).toHaveBeenCalledTimes(1);
  });

  // spec:web-ui/host-network-containment-in-the-console/without-host-isolate-the-state-is-shown-and-the-action-is-not
  it("offers no action without host.isolate, but still shows the badge", async () => {
    vi.spyOn(api, "getHostContainment").mockResolvedValue(contained);
    renderControl(["host.read"]);
    expect(await screen.findByText("Contained")).toBeVisible();
    expect(screen.queryByRole("button", { name: /Contain host|Release host/ })).toBeNull();
  });

  it("shows nothing when the state cannot be read", async () => {
    const read = vi.spyOn(api, "getHostContainment").mockRejectedValue(new Error("down"));
    renderControl();
    await waitFor(() => {
      expect(read).toHaveBeenCalled();
    });
    expect(screen.queryByRole("button", { name: /Contain host|Release host/ })).toBeNull();
  });

  // spec:web-ui/host-network-containment-in-the-console/an-operator-contains-a-host-from-its-page
  it("contains the host with a reason, then follows the delivery until the host confirms it", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const read = vi.spyOn(api, "getHostContainment").mockResolvedValue(never);
    const set = vi.spyOn(api, "setHostContainment").mockResolvedValue({
      state: { host_id: HOST, contained: true, version: 1, epoch: 100, reason: "beaconing" },
      changed: true,
      command_id: 7,
    });
    renderControl();

    fireEvent.click(await screen.findByRole("button", { name: "Contain host" }));
    const dialog = screen.getByRole("dialog", { name: "Contain this host?" });
    expect(dialog).toHaveTextContent("loses network access except to the EDR server");
    expect(lastButton("Contain host")).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Reason (required for audit log)"), { target: { value: "  beaconing  " } });
    fireEvent.click(lastButton("Contain host"));

    read.mockResolvedValue(pendingContain);
    await waitFor(() => {
      // Version 0 is the state this page read: a host never contained. Sending it is what makes the change conditional on the view
      // the operator acted from (issue #1076).
      expect(set).toHaveBeenCalledWith(HOST, true, "beaconing", 0);
    });
    expect(await screen.findByText("Containing")).toBeVisible();
    expect(screen.getByText("Containing").closest("[aria-live]")).toHaveAttribute("aria-live", "polite");

    read.mockResolvedValue(contained);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000);
    });
    expect(await screen.findByText("Contained")).toBeVisible();
    expect(screen.getByRole("button", { name: "Release host" })).toBeVisible();
    const reads = read.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(9000);
    });
    expect(read.mock.calls).toHaveLength(reads);
  });

  // spec:web-ui/host-network-containment-in-the-console/a-contained-host-can-be-released
  it("releases a contained host", async () => {
    vi.spyOn(api, "getHostContainment").mockResolvedValue(contained);
    const set = vi.spyOn(api, "setHostContainment").mockResolvedValue({
      state: { host_id: HOST, contained: false, version: 2, epoch: 200 },
      changed: true,
      command_id: 8,
    });
    renderControl();

    fireEvent.click(await screen.findByRole("button", { name: "Release host" }));
    vi.mocked(api.getHostContainment).mockResolvedValue({
      host_id: HOST, contained: false, version: 2, epoch: 200, delivery: { command_id: 8, status: "pending", current: true },
    });
    expect(screen.getByRole("dialog", { name: "Release this host?" })).toBeVisible();
    fireEvent.change(screen.getByLabelText("Reason (required for audit log)"), { target: { value: "reimaged" } });
    fireEvent.click(lastButton("Release host"));
    await waitFor(() => {
      expect(set).toHaveBeenCalledWith(HOST, false, "reimaged", 1);
    });
    expect(await screen.findByText("Releasing")).toBeVisible();
  });

  it("announces a release it followed to completion, and says nothing for a host already released", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const releasedState: ContainmentState = {
      host_id: HOST, contained: false, version: 2, epoch: 200, delivery: { command_id: 8, status: "completed", current: true },
    };
    const read = vi.spyOn(api, "getHostContainment").mockResolvedValue(releasedState);
    const { unmount } = renderControl();
    expect(await screen.findByRole("button", { name: "Contain host" })).toBeVisible();
    expect(screen.queryByText("Released")).toBeNull();
    unmount();

    read.mockResolvedValueOnce(contained).mockResolvedValue(releasedState);
    vi.spyOn(api, "setHostContainment").mockResolvedValue({
      state: { host_id: HOST, contained: false, version: 2, epoch: 200 },
      changed: true,
      command_id: 8,
    });
    renderControl();
    fireEvent.click(await screen.findByRole("button", { name: "Release host" }));
    fireEvent.change(screen.getByLabelText("Reason (required for audit log)"), { target: { value: "reimaged" } });
    fireEvent.click(lastButton("Release host"));
    const announcement = await screen.findByText("Released");
    expect(announcement).toHaveClass("host-containment__sr-only");
    expect(announcement.closest("[aria-live]")).toHaveAttribute("aria-live", "polite");
    expect(screen.queryByText("Releasing")).toBeNull();

    // A new change clears the announcement at once, not when the read that follows it returns.
    read.mockImplementation(() => new Promise<ContainmentState>(() => undefined));
    vi.mocked(api.setHostContainment).mockResolvedValue({ state: pendingContain, changed: true, command_id: 9 });
    fireEvent.click(screen.getByRole("button", { name: "Contain host" }));
    fireEvent.change(screen.getByLabelText("Reason (required for audit log)"), { target: { value: "beaconing again" } });
    fireEvent.click(lastButton("Contain host"));
    expect(await screen.findByText("Containing")).toBeVisible();
    expect(screen.queryByText("Released")).toBeNull();
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
  });

  it("reads one at a time while a change is on its way", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let answer: (s: ContainmentState) => void = () => undefined;
    const read = vi.spyOn(api, "getHostContainment")
      .mockResolvedValueOnce(pendingContain)
      .mockImplementationOnce(() => new Promise<ContainmentState>((resolve) => { answer = resolve; }));
    renderControl();
    expect(await screen.findByText("Containing")).toBeVisible();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(12000);
    });
    expect(read).toHaveBeenCalledTimes(2);
    read.mockResolvedValue(contained);
    await act(async () => {
      answer(contained);
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(await screen.findByText("Contained")).toBeVisible();
  });

  it("keeps following a change through a failed read", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const read = vi.spyOn(api, "getHostContainment").mockResolvedValue(never);
    vi.spyOn(api, "setHostContainment").mockResolvedValue({ state: pendingContain, changed: true, command_id: 7 });
    renderControl();
    fireEvent.click(await screen.findByRole("button", { name: "Contain host" }));
    fireEvent.change(screen.getByLabelText("Reason (required for audit log)"), { target: { value: "beaconing" } });
    read.mockRejectedValueOnce(new Error("blip")).mockResolvedValue(contained);
    fireEvent.click(lastButton("Contain host"));
    expect(await screen.findByText("Containing")).toBeVisible();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000);
    });
    expect(await screen.findByText("Contained")).toBeVisible();
  });

  it("shows why a change was refused in the confirmation", async () => {
    vi.spyOn(api, "getHostContainment").mockResolvedValue(never);
    const refusal = new Error("This host is no longer enrolled, so its containment cannot be changed.");
    vi.spyOn(api, "setHostContainment").mockRejectedValue(refusal);
    renderControl();
    fireEvent.click(await screen.findByRole("button", { name: "Contain host" }));
    fireEvent.change(screen.getByLabelText("Reason (required for audit log)"), { target: { value: "beaconing" } });
    fireEvent.click(lastButton("Contain host"));
    expect(await screen.findByRole("alert")).toHaveTextContent("no longer enrolled");
    expect(screen.getByRole("dialog", { name: "Contain this host?" })).toBeVisible();
  });

  it("reports a host someone else changed, and shows the state that now stands", async () => {
    // The follow-up read never resolves, so what the page shows afterwards can only have come from the conflict payload. With a read
    // that resolves, this test would pass with setState(err.state) deleted, which is the thing it is here to check.
    const read = vi.spyOn(api, "getHostContainment").mockResolvedValueOnce(contained).mockReturnValue(new Promise(() => {}));
    // Another operator released the host after this page read it contained, so the change this page asks for is refused.
    const released: ContainmentState = { host_id: HOST, contained: false, version: 2, epoch: 200, reason: "cleared" };
    const set = vi
      .spyOn(api, "setHostContainment")
      .mockRejectedValue(new api.ContainmentVersionConflictError("Someone else changed this host's containment.", released));
    renderControl();

    fireEvent.click(await screen.findByRole("button", { name: "Release host" }));
    fireEvent.change(screen.getByLabelText("Reason (required for audit log)"), { target: { value: "done" } });
    fireEvent.click(lastButton("Release host"));

    await waitFor(() => {
      expect(set).toHaveBeenCalledWith(HOST, false, "done", 1);
    });
    expect(await screen.findByText("Someone else changed this host's containment.")).toBeVisible();

    // The page took the state from the refusal, so the dialog now offers the decision that makes sense against what the host holds:
    // it was opened to release a contained host and now offers to contain a released one.
    expect(await screen.findByRole("dialog", { name: "Contain this host?" })).toBeVisible();
    expect(read).toHaveBeenCalled();
  });

  // spec:web-ui/host-network-containment-in-the-console/a-contained-host-whose-names-are-not-filtered-says-so
  //
  // A contained host whose DNS proxy is off still reaches only its own resolvers, but every name they answer resolves. Read from live
  // health, so it stays true after the containment completed rather than freezing at the moment the command finished (issue #1078).
  it("says when a contained host's names are not filtered, and explains it on a keyboard", async () => {
    vi.spyOn(api, "getHostContainment").mockResolvedValue(contained);
    renderControl(["host.read", "host.isolate"], healthWith([{ type: "dns_proxy", status: "healthy", reason: "provider_disabled", last_transition_ns: 0 }]));

    expect(await screen.findByText("Contained")).toBeVisible();
    const caveat = screen.getByRole("button", { name: /DNS by destination only/ });
    expect(caveat).toBeVisible();
    // The explanation is in the accessible name, so it is read without pressing anything, and pressing reveals it on screen.
    expect(caveat).toHaveAccessibleName(/not restricting which names/);
    expect(screen.queryByRole("note")).not.toBeInTheDocument();
    fireEvent.click(caveat);
    expect(screen.getByRole("note")).toBeVisible();
  });

  it.each([
    ["the proxy is capturing", healthWith([{ type: "dns_proxy", status: "healthy", reason: "activated", last_transition_ns: 0 }])],
    ["health has not been read", null],
  ])("says nothing about name filtering when %s", async (_name, health) => {
    vi.spyOn(api, "getHostContainment").mockResolvedValue(contained);
    renderControl(["host.read", "host.isolate"], health);

    await screen.findByRole("button", { name: "Release host" });
    expect(screen.queryByText("DNS by destination only")).not.toBeInTheDocument();
  });

  // A containment still on its way says nothing: the caveat qualifies what Contained means, and this host is not contained yet.
  it("says nothing about name filtering while the containment is on its way", async () => {
    vi.spyOn(api, "getHostContainment").mockResolvedValue(pendingContain);
    renderControl(["host.read", "host.isolate"], healthWith([{ type: "dns_proxy", status: "healthy", reason: "provider_disabled", last_transition_ns: 0 }]));

    expect(await screen.findByText("Containing")).toBeVisible();
    expect(screen.queryByText("DNS by destination only")).not.toBeInTheDocument();
  });
});
