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
  it("lists destinations and keeps the secret field write-only", async () => {
    vi.spyOn(api, "listWebhooks").mockResolvedValue([dest]);
    render(<Webhooks />);
    expect(await screen.findByText("pd")).toBeInTheDocument();
    expect(screen.getByText("https://hooks.example.com/edr")).toBeInTheDocument();
    // The signing secret is never rendered: the field is empty even though a secret is set.
    expect(screen.getByLabelText("Signing secret")).toHaveValue("");
  });

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
    expect(create.mock.calls[0][0]).toMatchObject({
      name: "pd",
      url: "https://hooks.example.com/edr",
      secret: "sekret",
      event_types: ["alert.created"],
    });
    expect(await screen.findByText("pd")).toBeInTheDocument();
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
    ]);
    render(<Webhooks />);
    await screen.findByText("pd");

    fireEvent.click(screen.getByRole("button", { name: "Deliveries" }));
    expect(await screen.findByText("receiver unavailable")).toBeInTheDocument();
    expect(screen.getByText("failed")).toBeInTheDocument();
  });
});
