import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import * as api from "../../api";
import { Webhooks } from "./Webhooks";

const dest: api.WebhookDestination = {
  id: 1,
  name: "pd",
  url: "https://hooks.example.com/edr",
  event_types: ["alert.created"],
  min_severity: "high",
  enabled: true,
  secret_set: true,
  created_at: "",
  updated_at: "",
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe("Webhooks", () => {
  // spec:web-ui/the-settings-area-manages-webhook-destinations/the-secret-field-is-write-only
  it("lists destinations and keeps the secret field write-only", async () => {
    vi.spyOn(api, "listWebhooks").mockResolvedValue([dest]);
    render(<Webhooks />);
    expect(await screen.findByText("pd")).toBeInTheDocument();
    expect(screen.getByText("https://hooks.example.com/edr")).toBeInTheDocument();
    expect(screen.getByLabelText("Signing secret")).toHaveValue("");
  });

  it("renders a load error", async () => {
    vi.spyOn(api, "listWebhooks").mockRejectedValue(new Error("nope"));
    render(<Webhooks />);
    expect(await screen.findByRole("alert")).toHaveTextContent("nope");
  });

  it("shows a disabled destination with a disabled badge", async () => {
    vi.spyOn(api, "listWebhooks").mockResolvedValue([{ ...dest, enabled: false }]);
    render(<Webhooks />);
    expect(await screen.findByText("Disabled")).toBeInTheDocument();
  });

  // spec:web-ui/the-settings-area-manages-webhook-destinations/an-admin-adds-a-destination-from-the-settings-area
  it("creates a destination and refreshes the list", async () => {
    vi.spyOn(api, "listWebhooks").mockResolvedValueOnce([]).mockResolvedValueOnce([dest]);
    const create = vi.spyOn(api, "createWebhook").mockResolvedValue(dest);
    render(<Webhooks />);
    await screen.findByText("No destinations configured.");

    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "pd" } });
    fireEvent.change(screen.getByLabelText("URL"), { target: { value: "https://hooks.example.com/edr" } });
    fireEvent.change(screen.getByLabelText("Signing secret"), { target: { value: "sekret" } });
    fireEvent.click(screen.getByRole("button", { name: "Add destination" }));

    await waitFor(() => {
      expect(create).toHaveBeenCalledTimes(1);
    });
    expect(create.mock.calls[0][0]).toMatchObject({ name: "pd", secret: "sekret", event_types: ["alert.created"] });
    expect(await screen.findByText("Saved.")).toBeInTheDocument();
  });

  it("surfaces a save error", async () => {
    vi.spyOn(api, "listWebhooks").mockResolvedValue([]);
    vi.spyOn(api, "createWebhook").mockRejectedValue(new Error("boom"));
    render(<Webhooks />);
    await screen.findByText("No destinations configured.");
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "x" } });
    fireEvent.change(screen.getByLabelText("URL"), { target: { value: "https://ok.example.com" } });
    fireEvent.change(screen.getByLabelText("Signing secret"), { target: { value: "s" } });
    fireEvent.click(screen.getByRole("button", { name: "Add destination" }));
    expect(await screen.findByText("boom")).toBeInTheDocument();
  });

  it("rejects a non-https URL before calling the API", async () => {
    vi.spyOn(api, "listWebhooks").mockResolvedValue([]);
    const create = vi.spyOn(api, "createWebhook");
    render(<Webhooks />);
    await screen.findByText("No destinations configured.");
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "x" } });
    fireEvent.change(screen.getByLabelText("URL"), { target: { value: "http://insecure.example.com" } });
    fireEvent.change(screen.getByLabelText("Signing secret"), { target: { value: "s" } });
    fireEvent.click(screen.getByRole("button", { name: "Add destination" }));
    expect(await screen.findByText("URL must be a valid https URL.")).toBeInTheDocument();
    expect(create).not.toHaveBeenCalled();
  });

  it("requires a name and at least one event type", async () => {
    vi.spyOn(api, "listWebhooks").mockResolvedValue([]);
    render(<Webhooks />);
    await screen.findByText("No destinations configured.");

    // No name.
    fireEvent.click(screen.getByRole("button", { name: "Add destination" }));
    expect(await screen.findByText("Name is required.")).toBeInTheDocument();

    // Name + url + secret but no event type selected.
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "x" } });
    fireEvent.change(screen.getByLabelText("URL"), { target: { value: "https://ok.example.com" } });
    fireEvent.change(screen.getByLabelText("Signing secret"), { target: { value: "s" } });
    fireEvent.click(screen.getByLabelText("Alert created")); // uncheck the default
    fireEvent.click(screen.getByRole("button", { name: "Add destination" }));
    expect(await screen.findByText("Select at least one event type.")).toBeInTheDocument();

    // Create with the secret cleared.
    fireEvent.click(screen.getByLabelText("Alert created")); // re-check
    fireEvent.change(screen.getByLabelText("Signing secret"), { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: "Add destination" }));
    expect(await screen.findByText("A signing secret is required.")).toBeInTheDocument();
  });

  it("edits a destination, keeping the secret when left blank", async () => {
    vi.spyOn(api, "listWebhooks").mockResolvedValue([dest]);
    const update = vi.spyOn(api, "updateWebhook").mockResolvedValue({ ...dest, name: "pd-renamed" });
    render(<Webhooks />);
    await screen.findByText("pd");

    fireEvent.click(screen.getByRole("button", { name: "Edit" }));
    // The form is populated from the destination; the secret stays write-only (blank).
    expect(screen.getByLabelText("Name")).toHaveValue("pd");
    expect(screen.getByLabelText("Signing secret")).toHaveValue("");
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "pd-renamed" } });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() => {
      expect(update).toHaveBeenCalledTimes(1);
    });
    expect(update.mock.calls[0][0]).toBe(1);
    expect(update.mock.calls[0][1]).not.toHaveProperty("secret");
  });

  it("cancels an edit and resets the form", async () => {
    vi.spyOn(api, "listWebhooks").mockResolvedValue([dest]);
    render(<Webhooks />);
    await screen.findByText("pd");
    fireEvent.click(screen.getByRole("button", { name: "Edit" }));
    expect(screen.getByLabelText("Name")).toHaveValue("pd");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.getByLabelText("Name")).toHaveValue("");
    expect(screen.getByRole("button", { name: "Add destination" })).toBeInTheDocument();
  });

  it("deletes only after confirmation", async () => {
    vi.spyOn(api, "listWebhooks").mockResolvedValueOnce([dest]).mockResolvedValueOnce([]);
    const del = vi.spyOn(api, "deleteWebhook").mockResolvedValue();
    const confirm = vi.spyOn(globalThis, "confirm").mockReturnValueOnce(false).mockReturnValueOnce(true);
    render(<Webhooks />);
    await screen.findByText("pd");

    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(del).not.toHaveBeenCalled(); // declined

    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => {
      expect(del).toHaveBeenCalledWith(1);
    });
    expect(await screen.findByText("No destinations configured.")).toBeInTheDocument();
  });

  it("shows the per-destination delivery-status readout", async () => {
    vi.spyOn(api, "listWebhooks").mockResolvedValue([dest]);
    vi.spyOn(api, "listWebhookDeliveries").mockResolvedValue([
      {
        id: 9,
        destination_id: 1,
        event_type: "alert.created",
        status: "failed",
        attempt: 3,
        last_status_code: 503,
        last_error: "receiver unavailable",
        created_at: "",
        updated_at: "",
        next_attempt_at: "",
      },
      {
        id: 10,
        destination_id: 1,
        event_type: "alert.created",
        status: "pending",
        attempt: 0,
        created_at: "",
        updated_at: "",
        next_attempt_at: "",
      },
    ]);
    render(<Webhooks />);
    await screen.findByText("pd");
    fireEvent.click(screen.getByRole("button", { name: "Deliveries" }));
    expect(await screen.findByText("receiver unavailable")).toBeInTheDocument();
    expect(screen.getByText("failed")).toBeInTheDocument();
    // The pending row has no status code, rendering the "-" fallback.
    expect(screen.getByText("-")).toBeInTheDocument();
  });

  // spec:web-ui/the-settings-area-manages-webhook-destinations/an-operator-tests-a-destination-from-the-ui
  it("sends a test delivery and shows the outcome", async () => {
    vi.spyOn(api, "listWebhooks").mockResolvedValue([dest]);
    const send = vi.spyOn(api, "testWebhook").mockResolvedValue({ ok: true, status_code: 200 });
    render(<Webhooks />);
    await screen.findByText("pd");
    fireEvent.click(screen.getByRole("button", { name: "Send test" }));
    await waitFor(() => {
      expect(send).toHaveBeenCalledWith(1);
    });
    expect(await screen.findByText("Delivered (200)")).toBeInTheDocument();
  });

  it("shows a failed test delivery outcome", async () => {
    vi.spyOn(api, "listWebhooks").mockResolvedValue([dest]);
    vi.spyOn(api, "testWebhook").mockResolvedValue({ ok: false, error: "connection refused" });
    render(<Webhooks />);
    await screen.findByText("pd");
    fireEvent.click(screen.getByRole("button", { name: "Send test" }));
    expect(await screen.findByText("connection refused")).toBeInTheDocument();
  });

  it("shows the HTTP status code when a test delivery fails without an error message", async () => {
    vi.spyOn(api, "listWebhooks").mockResolvedValue([dest]);
    // A non-2xx receiver response carries no transport error, so the status code is the only diagnostic to surface.
    vi.spyOn(api, "testWebhook").mockResolvedValue({ ok: false, status_code: 500 });
    render(<Webhooks />);
    await screen.findByText("pd");
    fireEvent.click(screen.getByRole("button", { name: "Send test" }));
    expect(await screen.findByText("Failed (500)")).toBeInTheDocument();
  });

  it("falls back to a generic message when a failed test has neither error nor status code", async () => {
    vi.spyOn(api, "listWebhooks").mockResolvedValue([dest]);
    // The ultimate fallback arm: not ok, and the response carries no diagnostic detail at all.
    vi.spyOn(api, "testWebhook").mockResolvedValue({ ok: false });
    render(<Webhooks />);
    await screen.findByText("pd");
    fireEvent.click(screen.getByRole("button", { name: "Send test" }));
    expect(await screen.findByText("Test delivery failed")).toBeInTheDocument();
  });

  it("surfaces a thrown error from the test-send request", async () => {
    vi.spyOn(api, "listWebhooks").mockResolvedValue([dest]);
    // A rejected request (e.g. a network failure before any response) is caught and shown to the operator.
    vi.spyOn(api, "testWebhook").mockRejectedValue(new Error("network down"));
    render(<Webhooks />);
    await screen.findByText("pd");
    fireEvent.click(screen.getByRole("button", { name: "Send test" }));
    expect(await screen.findByText("network down")).toBeInTheDocument();
  });

  it("surfaces a deliveries load error", async () => {
    vi.spyOn(api, "listWebhooks").mockResolvedValue([dest]);
    vi.spyOn(api, "listWebhookDeliveries").mockRejectedValue(new Error("delivery boom"));
    render(<Webhooks />);
    await screen.findByText("pd");
    fireEvent.click(screen.getByRole("button", { name: "Deliveries" }));
    expect(await screen.findByText("delivery boom")).toBeInTheDocument();
  });
});
