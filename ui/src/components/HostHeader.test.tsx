import { describe, it, expect, vi, afterEach, beforeEach, onTestFinished } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";

import { HostHeader } from "./HostHeader";
import * as api from "../api";
import type { HostDetail, HostHealth } from "../types";

const NANOSECONDS_PER_MILLISECOND = 1_000_000;
const MINUTE_MS = 60 * 1000;

function detailFixture(overrides: Partial<HostDetail> = {}): HostDetail {
  return {
    host_id: "93DFC6F5-763D-5075-B305-8AC145D12F96",
    hostname: "mac-01.local",
    platform: "darwin",
    os_name: "macOS",
    os_version: "26.4",
    os_build: "25E123",
    agent_version: "0.5.0",
    source_ip: "203.0.113.7",
    enrolled_at_ns: new Date("2026-06-01T12:00:00Z").getTime() * NANOSECONDS_PER_MILLISECOND,
    inventory_reported_at_ns: Date.now() * NANOSECONDS_PER_MILLISECOND,
    event_count: 12345,
    last_seen_ns: Date.now() * NANOSECONDS_PER_MILLISECOND,
    overall_status: "healthy",
    ...overrides,
  };
}

function renderHeader(hostId: string) {
  return render(
    <MemoryRouter initialEntries={[`/hosts/${hostId}`]}>
      <HostHeader hostId={hostId} />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  // The header's containment control reads its own state; these tests are about the rest of the header.
  vi.spyOn(api, "getHostContainment").mockResolvedValue({ host_id: "", contained: false, version: 0, epoch: 0 });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("HostHeader", () => {
  // spec:web-ui/host-detail-header/header-shows-identity-for-an-enrolled-host
  it("shows hostname + online pill + OS, and keeps reference facts in the Details popover", async () => {
    const detail = detailFixture();
    vi.spyOn(api, "getHostDetail").mockResolvedValue(detail);
    renderHeader(detail.host_id);

    // At a glance: identity, status, and OS only. The online pill conveys liveness, so no "last seen" segment when online.
    expect(await screen.findByText("mac-01.local")).toBeInTheDocument();
    expect(screen.getByText("online")).toBeInTheDocument();
    expect(screen.getByText("macOS 26.4 (25E123)")).toBeInTheDocument();
    expect(screen.queryByText(/last seen/)).not.toBeInTheDocument();

    // Reference facts (raw id + copy, agent, IP, events, enrolled) are hidden until the popover is opened, and the copy control is not
    // sitting next to the hostname.
    expect(screen.queryByText(detail.host_id)).not.toBeInTheDocument();
    expect(screen.queryByText("0.5.0")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Copy host id" })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Details" }));

    expect(screen.getByText(detail.host_id)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy host id" })).toBeInTheDocument();
    expect(screen.getByText("0.5.0")).toBeInTheDocument();
    expect(screen.getByText("203.0.113.7")).toBeInTheDocument();
    expect(screen.getByText((12345).toLocaleString())).toBeInTheDocument();
    expect(screen.getByText("Last seen")).toBeInTheDocument();
  });

  it("shows 'last seen' in the meta row only when the host is offline", async () => {
    const detail = detailFixture({
      last_seen_ns: (Date.now() - 10 * 60 * 1000) * NANOSECONDS_PER_MILLISECOND,
    });
    vi.spyOn(api, "getHostDetail").mockResolvedValue(detail);
    renderHeader(detail.host_id);

    expect(await screen.findByText("offline")).toBeInTheDocument();
    // Offline: staleness matters, so the exact age surfaces in the always-visible meta row.
    expect(screen.getByText(/^last seen \d+m ago$/)).toBeInTheDocument();
  });

  it("drops unknown facts rather than rendering empty segments", async () => {
    const detail = detailFixture({
      hostname: "",
      os_name: "",
      os_version: "",
      os_build: "",
      agent_version: "",
      source_ip: "",
      enrolled_at_ns: 0,
      last_seen_ns: (Date.now() - 10 * 60 * 1000) * NANOSECONDS_PER_MILLISECOND,
    });
    vi.spyOn(api, "getHostDetail").mockResolvedValue(detail);
    renderHeader(detail.host_id);

    // Never-enrolled host: the id takes the title slot; unknown facts (agent, IP, enrolled) render no popover row at all.
    expect(await screen.findByText(detail.host_id)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Details" }));
    expect(screen.queryByText("Agent")).not.toBeInTheDocument();
    expect(screen.queryByText("IP")).not.toBeInTheDocument();
    expect(screen.queryByText("Enrolled")).not.toBeInTheDocument();
  });

  // spec:web-ui/host-detail-header/header-degrades-when-the-detail-fetch-fails
  it("falls back to the host id title when the detail fetch fails", async () => {
    vi.spyOn(api, "getHostDetail").mockRejectedValue(new Error("boom"));
    renderHeader("HOST-XYZ");

    expect(await screen.findByText("HOST-XYZ")).toBeInTheDocument();
    expect(screen.queryByText("online")).not.toBeInTheDocument();
    expect(screen.queryByText("offline")).not.toBeInTheDocument();
    // With no detail there is nothing to disclose, so no Details trigger renders; the raw-id title is itself selectable.
    expect(screen.queryByRole("button", { name: "Details" })).not.toBeInTheDocument();
  });
});

function healthFixture(overrides: Partial<HostHealth> = {}): HostHealth {
  return {
    overall_status: "healthy",
    reported_at_ns: Date.now() * NANOSECONDS_PER_MILLISECOND,
    components: [],
    derived_components: null,
    episodes: [],
    ...overrides,
  };
}

// Agent health rides inside the host Details popover, not a standalone card: the trigger carries an attention dot only when the rollup is
// not healthy, and opening the popover reveals the rollup pill plus the per-component conditions. These pin the reworked surface that
// replaced HostHealthPanel.
describe("HostHeader agent health", () => {
  // spec:web-ui/the-host-detail-surfaces-the-health-conditions/the-detail-lists-a-component-with-its-message-and-age
  it("flags an unhealthy agent with an attention dot and lists each component's message and age when opened", async () => {
    const detail = detailFixture();
    vi.spyOn(api, "getHostDetail").mockResolvedValue(detail);
    vi.spyOn(api, "getHostHealth").mockResolvedValue(
      healthFixture({
        overall_status: "unhealthy",
        components: [
          {
            type: "endpoint_security_extension",
            status: "unhealthy",
            reason: "never_connected",
            message: "Security extension not activated",
            last_transition_ns: (Date.now() - 5 * MINUTE_MS) * NANOSECONDS_PER_MILLISECOND,
          },
          {
            type: "network_extension",
            status: "healthy",
            reason: "activated",
            message: "Network extension connected",
            last_transition_ns: Date.now() * NANOSECONDS_PER_MILLISECOND,
          },
        ],
      }),
    );
    renderHeader(detail.host_id);

    // The unhealthy rollup surfaces as an attention marker on the always-visible trigger, before the popover is even opened.
    const trigger = await screen.findByRole("button", { name: /Details/ });
    await waitFor(() => {
      expect(trigger).toHaveAttribute("title", "Agent needs attention");
    });

    fireEvent.click(trigger);

    // Opening reveals the self-describing rollup pill plus the failing component with its friendly label, message, and age.
    expect(screen.getByText("Agent needs attention")).toBeInTheDocument();
    expect(screen.getByText("Security extension")).toBeInTheDocument();
    expect(screen.getByText("Security extension not activated")).toBeInTheDocument();
    expect(screen.getByText("5m ago")).toBeInTheDocument();
    expect(screen.getByText("Network extension")).toBeInTheDocument();
  });

  // spec:web-ui/the-host-detail-surfaces-the-health-conditions/a-fully-healthy-host-shows-a-single-healthy-rollup
  it("shows no attention dot when healthy and reveals the single healthy rollup on demand", async () => {
    const detail = detailFixture();
    vi.spyOn(api, "getHostDetail").mockResolvedValue(detail);
    vi.spyOn(api, "getHostHealth").mockResolvedValue(
      healthFixture({
        components: [
          {
            type: "endpoint_security_extension",
            status: "healthy",
            reason: "activated",
            message: "Security extension connected",
            last_transition_ns: Date.now() * NANOSECONDS_PER_MILLISECOND,
          },
        ],
      }),
    );
    renderHeader(detail.host_id);

    fireEvent.click(await screen.findByRole("button", { name: "Details" }));

    // A healthy agent rolls up to one pill, revealed only on demand; the per-component condition is available once the popover is open.
    expect(await screen.findByText("Agent healthy")).toBeInTheDocument();
    expect(screen.getByText("Security extension connected")).toBeInTheDocument();
    // Health is now loaded and healthy, so the always-visible trigger carries no attention marker.
    expect(screen.getByRole("button", { name: "Details" })).not.toHaveAttribute("title");
  });

  it("uses an amber (not red) attention dot when the agent is degraded", async () => {
    const detail = detailFixture();
    vi.spyOn(api, "getHostDetail").mockResolvedValue(detail);
    vi.spyOn(api, "getHostHealth").mockResolvedValue(healthFixture({ overall_status: "degraded" }));
    renderHeader(detail.host_id);

    const trigger = await screen.findByRole("button", { name: /Details/ });
    await waitFor(() => {
      expect(trigger).toHaveAttribute("title", "Agent needs attention");
    });
    // The dot's tone distinguishes a degraded agent (amber --warn) from a fully unhealthy one (red --crit).
    expect(trigger.querySelector(".host-header__health-dot--warn")).not.toBeNull();
    expect(trigger.querySelector(".host-header__health-dot--crit")).toBeNull();
  });

  it("carries no attention marker when health is unknown", async () => {
    const detail = detailFixture();
    vi.spyOn(api, "getHostDetail").mockResolvedValue(detail);
    vi.spyOn(api, "getHostHealth").mockResolvedValue(healthFixture({ overall_status: "unknown", components: null }));
    renderHeader(detail.host_id);

    // Unknown means no snapshot yet, nothing actionable: open the popover to prove health resolved, then assert the trigger stays clean.
    fireEvent.click(await screen.findByRole("button", { name: "Details" }));
    expect(await screen.findByText("Agent unknown")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Details" })).not.toHaveAttribute("title");
  });

  // Server-derived conditions (issue #677). These are the ones the agent cannot report about itself: it believes it is healthy, and
  // the contradiction is only visible from the server's side of the wire.
  it("lists a server-derived condition alongside the agent's own, and lets it drive the attention dot", async () => {
    const detail = detailFixture();
    vi.spyOn(api, "getHostDetail").mockResolvedValue(detail);
    vi.spyOn(api, "getHostHealth").mockResolvedValue(
      healthFixture({
        // The rollup already folds the derived condition in, which is what turns a host the agent called healthy amber.
        overall_status: "degraded",
        components: [
          {
            type: "network_extension",
            status: "healthy",
            reason: "activated",
            message: "Network extension connected",
            last_transition_ns: (Date.now() - 5 * MINUTE_MS) * NANOSECONDS_PER_MILLISECOND,
          },
        ],
        derived_components: [
          {
            type: "dns_proxy_delivery",
            status: "degraded",
            reason: "no_flow_telemetry",
            message: "reports healthy, but no dns_query events reached the server in the last 2h",
            last_transition_ns: 0,
          },
        ],
      }),
    );
    renderHeader(detail.host_id);

    fireEvent.click(await screen.findByRole("button", { name: "Details" }));

    // Both conditions are present, so an operator sees the agent's claim and the server's contradiction of it side by side.
    expect(await screen.findByText("Network extension connected")).toBeInTheDocument();
    expect(screen.getByText("DNS capture")).toBeInTheDocument();
    expect(
      screen.getByText("reports healthy, but no dns_query events reached the server in the last 2h"),
    ).toBeInTheDocument();
  });

  // A derived condition has no observed transition instant, so it carries last_transition_ns 0. Rendering that through the relative
  // formatter would date a fault that may be days old to the moment the page loaded, which is worse than showing no age at all.
  it("renders no age for a derived condition, which has no transition instant", async () => {
    const detail = detailFixture();
    vi.spyOn(api, "getHostDetail").mockResolvedValue(detail);
    vi.spyOn(api, "getHostHealth").mockResolvedValue(
      healthFixture({
        overall_status: "degraded",
        components: [],
        derived_components: [
          {
            type: "content_filter_delivery",
            status: "degraded",
            reason: "no_flow_telemetry",
            message: "reports healthy, but no network_connect events reached the server in the last 2h",
            last_transition_ns: 0,
          },
        ],
      }),
    );
    const { container } = renderHeader(detail.host_id);

    fireEvent.click(await screen.findByRole("button", { name: "Details" }));
    expect(await screen.findByText("Connection capture")).toBeInTheDocument();

    // The age element is absent entirely rather than rendering an epoch-relative string.
    expect(container.querySelector(".host-header__health-since")).toBeNull();
  });

  it("shows nothing derived when the server has nothing to add", async () => {
    const detail = detailFixture();
    vi.spyOn(api, "getHostDetail").mockResolvedValue(detail);
    vi.spyOn(api, "getHostHealth").mockResolvedValue(
      healthFixture({
        components: [
          {
            type: "network_extension",
            status: "healthy",
            reason: "activated",
            message: "Network extension connected",
            last_transition_ns: Date.now() * NANOSECONDS_PER_MILLISECOND,
          },
        ],
      }),
    );
    renderHeader(detail.host_id);

    fireEvent.click(await screen.findByRole("button", { name: "Details" }));

    expect(await screen.findByText("Agent healthy")).toBeInTheDocument();
    expect(screen.queryByText("DNS capture")).not.toBeInTheDocument();
    expect(screen.queryByText("Connection capture")).not.toBeInTheDocument();
  });

  // Agent-reported providers (issue #702) render beside the extension that owns them, so an operator sees which capture is
  // down rather than only that something under the network extension is.
  // spec:web-ui/the-host-detail-surfaces-the-health-conditions/the-detail-lists-recorded-sensor-faults
  //
  // A recorded fault is listed with the part at fault, why the repair gave up, and when: an open one by how long ago it began, and a
  // resolved one by how long it LASTED, which is the number the record exists to give. Both open and resolved are fed, in that order,
  // to pin that an open fault is not buried under the resolved history.
  it("lists recorded sensor faults, open ones by when they began and resolved ones by how long they lasted", async () => {
    const detail = detailFixture();
    const nowNs = Date.now() * NANOSECONDS_PER_MILLISECOND;
    vi.spyOn(api, "getHostDetail").mockResolvedValue(detail);
    vi.spyOn(api, "getHostHealth").mockResolvedValue(
      healthFixture({
        overall_status: "unhealthy",
        episodes: [
          {
            id: 2,
            kind: "self_heal_failed",
            component: "network_extension",
            subject: "dns_proxy",
            severity: "critical",
            title: "EDR sensor could not be restored",
            detail: { provider: "dns_proxy", outcome: "enable_failed", attempts: 3 },
            // Mid-bucket, for the epoch-rounding reason given on the capture-provider test below.
            opened_at_ns: (Date.now() - 12 * MINUTE_MS - 30 * 1000) * NANOSECONDS_PER_MILLISECOND,
          },
          {
            id: 1,
            kind: "self_heal_failed",
            component: "network_extension",
            subject: "content_filter",
            severity: "critical",
            title: "EDR sensor could not be restored",
            detail: { provider: "content_filter", outcome: "enable_ineffective", attempts: 5 },
            opened_at_ns: nowNs - 3 * 3600 * 1000 * NANOSECONDS_PER_MILLISECOND,
            resolved_at_ns: nowNs - (3 * 3600 - 2 * 3600 - 14 * 60) * 1000 * NANOSECONDS_PER_MILLISECOND,
          },
        ],
      }),
    );
    renderHeader(detail.host_id);

    fireEvent.click(await screen.findByRole("button", { name: "Details" }));

    expect(await screen.findByText("Sensor faults")).toBeVisible();
    // The part at fault is the provider, labelled the way the component rows label it.
    expect(screen.getByText("DNS proxy")).toBeVisible();
    expect(screen.getByText("Content filter")).toBeVisible();
    // Why it gave up, in words, because the two outcomes point at different fixes.
    expect(screen.getByText("EDR sensor could not be restored: the repair command kept failing")).toBeVisible();
    expect(screen.getByText("EDR sensor could not be restored: repairs reported success but it stayed stopped")).toBeVisible();
    // Open: when it began. Resolved: how long it lasted, and when it ended.
    expect(screen.getByText("opened 12m ago")).toBeVisible();
    expect(screen.getByText(/^lasted 2h 14m, ended /)).toBeVisible();

    // Open before resolved.
    const items = screen.getByText("Sensor faults").parentElement?.querySelectorAll("li") ?? [];
    expect(items[0]?.textContent).toContain("DNS proxy");
    expect(items[1]?.textContent).toContain("Content filter");
  });

  // A host with no recorded faults renders no section at all, keeping the popover's rule that a clean host shows no health chrome.
  it("renders no sensor-fault section for a host with none recorded", async () => {
    const detail = detailFixture();
    vi.spyOn(api, "getHostDetail").mockResolvedValue(detail);
    vi.spyOn(api, "getHostHealth").mockResolvedValue(healthFixture({ episodes: [] }));
    renderHeader(detail.host_id);

    fireEvent.click(await screen.findByRole("button", { name: "Details" }));

    expect(await screen.findByText(/Agent healthy/)).toBeVisible();
    expect(screen.queryByText("Sensor faults")).toBeNull();
  });

  // spec:web-ui/the-host-detail-surfaces-the-health-conditions/a-recovered-host-keeps-its-fault-history-without-an-attention-marker
  //
  // A resolved fault on a host that is healthy NOW still appears. The component rows above have long since gone green; this list is the
  // record that says the host was once blind, which is the whole reason it exists apart from them. It also must not raise the attention
  // dot, which answers "does this host need someone now".
  it("keeps a resolved fault on a host that has recovered, without flagging the host", async () => {
    const detail = detailFixture();
    const nowNs = Date.now() * NANOSECONDS_PER_MILLISECOND;
    vi.spyOn(api, "getHostDetail").mockResolvedValue(detail);
    vi.spyOn(api, "getHostHealth").mockResolvedValue(
      healthFixture({
        overall_status: "healthy",
        episodes: [
          {
            id: 1,
            kind: "self_heal_failed",
            component: "network_extension",
            subject: "content_filter",
            severity: "critical",
            title: "EDR sensor could not be restored",
            opened_at_ns: nowNs - 2 * 3600 * 1000 * NANOSECONDS_PER_MILLISECOND,
            resolved_at_ns: nowNs - 3600 * 1000 * NANOSECONDS_PER_MILLISECOND,
          },
        ],
      }),
    );
    renderHeader(detail.host_id);

    const trigger = await screen.findByRole("button", { name: /Details/ });
    fireEvent.click(trigger);
    expect(await screen.findByText("Sensor faults")).toBeVisible();
    expect(screen.getByText(/^lasted 1h, ended /)).toBeVisible();
    expect(trigger).not.toHaveAttribute("title", "Agent needs attention");
  });

  // Episode fields are open-vocabulary values the agent reports. An inherited property name used as a lookup key into a plain label table
  // resolves to something that is not a label: "__proto__" yields Object.prototype, which React refuses to render, so one malformed or
  // compromised sensor report would crash the popover for every operator who opened it. Each hostile value must fall back to itself (or
  // to nothing, for an outcome) exactly as an unrecognised one does.
  it("renders hostile fault names as plain text instead of crashing", async () => {
    const detail = detailFixture();
    const nowNs = Date.now() * NANOSECONDS_PER_MILLISECOND;
    vi.spyOn(api, "getHostDetail").mockResolvedValue(detail);
    vi.spyOn(api, "getHostHealth").mockResolvedValue(
      healthFixture({
        overall_status: "unhealthy",
        components: [
          { type: "constructor", status: "unhealthy", message: "hostile component type", last_transition_ns: nowNs },
        ],
        episodes: [
          {
            id: 1,
            kind: "self_heal_failed",
            component: "network_extension",
            subject: "__proto__",
            severity: "critical",
            title: "EDR sensor could not be restored",
            detail: { outcome: "toString" },
            opened_at_ns: nowNs,
          },
        ],
      }),
    );
    renderHeader(detail.host_id);

    fireEvent.click(await screen.findByRole("button", { name: "Details" }));

    expect(await screen.findByText("Sensor faults")).toBeVisible();
    expect(screen.getByText("__proto__")).toBeVisible();
    // An inherited outcome name is not an outcome: the title stands alone, with no "[object]" or function source appended.
    expect(screen.getByText("EDR sensor could not be restored")).toBeVisible();
    expect(screen.getByText("constructor")).toBeVisible();
  });

  it("names each capture provider the agent reports", async () => {
    const detail = detailFixture();
    vi.spyOn(api, "getHostDetail").mockResolvedValue(detail);
    vi.spyOn(api, "getHostHealth").mockResolvedValue(
      healthFixture({
        overall_status: "unhealthy",
        components: [
          {
            type: "network_extension",
            status: "unhealthy",
            reason: "provider_stopped",
            message: "Network extension stopped capturing: dns_proxy",
            last_transition_ns: (Date.now() - 5 * MINUTE_MS) * NANOSECONDS_PER_MILLISECOND,
          },
          {
            type: "content_filter",
            status: "healthy",
            reason: "activated",
            message: "Content filter is capturing",
            last_transition_ns: (Date.now() - 30 * MINUTE_MS - 30 * 1000) * NANOSECONDS_PER_MILLISECOND,
          },
          {
            type: "dns_proxy",
            status: "unhealthy",
            reason: "provider_stopped",
            message: "DNS proxy stopped capturing",
            // Deliberately MID-bucket (5m30s) rather than exactly 5m. formatRelativeNs floors to whole minutes and these
            // epoch-nanosecond values exceed Number.MAX_SAFE_INTEGER, so a boundary-exact offset can round down to "4m ago"
            // and flake. Half a minute either side of the boundary makes the floored value stable.
            last_transition_ns: (Date.now() - 5 * MINUTE_MS - 30 * 1000) * NANOSECONDS_PER_MILLISECOND,
          },
        ],
      }),
    );
    renderHeader(detail.host_id);

    fireEvent.click(await screen.findByRole("button", { name: "Details" }));

    expect(await screen.findByText("Content filter")).toBeInTheDocument();
    expect(screen.getByText("DNS proxy")).toBeInTheDocument();
    expect(screen.getByText("DNS proxy stopped capturing")).toBeInTheDocument();
    // Agent-reported conditions carry a real transition instant, unlike derived ones, so their age renders.
    expect(screen.getAllByText("5m ago").length).toBeGreaterThan(0);
  });
});

// The header keys its containment control by host, so moving to another host on the same route closes an open confirmation instead
// of letting it act on the host now shown.
describe("HostHeader containment across hosts", () => {
  it("starts the containment control over when the host changes", async () => {
    const showModal = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, "showModal");
    const close = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, "close");
    onTestFinished(() => {
      for (const [name, descriptor] of [["showModal", showModal], ["close", close]] as const) {
        if (descriptor) Object.defineProperty(HTMLDialogElement.prototype, name, descriptor);
        else Reflect.deleteProperty(HTMLDialogElement.prototype, name);
      }
    });
    HTMLDialogElement.prototype.showModal = function showModalStandIn() {
      this.open = true;
    };
    HTMLDialogElement.prototype.close = function closeStandIn() {
      this.open = false;
    };
    vi.spyOn(api, "getHostDetail").mockResolvedValue(detailFixture());
    vi.spyOn(api, "getHostHealth").mockRejectedValue(new Error("unused"));
    const set = vi.spyOn(api, "setHostContainment");
    const { rerender } = render(
      <MemoryRouter>
        <HostHeader hostId="HOST-A" />
      </MemoryRouter>,
    );
    fireEvent.click(await screen.findByRole("button", { name: "Contain host" }));
    expect(screen.getByRole("dialog", { name: "Contain this host?" })).toBeVisible();

    rerender(
      <MemoryRouter>
        <HostHeader hostId="HOST-B" />
      </MemoryRouter>,
    );
    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: "Contain this host?" })).toBeNull();
    });
    expect(set).not.toHaveBeenCalled();
  });
});

