import { describe, it, expect, vi, afterEach } from "vitest";
import {
  listWebhooks,
  createWebhook,
  updateWebhook,
  deleteWebhook,
  listWebhookDeliveries,
  testWebhook,
  attachCsrfHeader,
  type WebhookDestinationInput,
} from "./api";

interface FakeResponse {
  ok: boolean;
  status: number;
  statusText: string;
  headers: { get(name: string): string | null };
  clone(): FakeResponse;
  json(): Promise<unknown>;
}

function stubFetch(body: unknown, status = 200): ReturnType<typeof vi.fn> {
  const fake: FakeResponse = {
    ok: status >= 200 && status < 300,
    status,
    statusText: "",
    headers: { get: () => null },
    clone(): FakeResponse {
      return fake;
    },
    json(): Promise<unknown> {
      return Promise.resolve(body);
    },
  };
  const mock = vi.fn().mockResolvedValue(fake);
  vi.stubGlobal("fetch", mock);
  return mock;
}

const input: WebhookDestinationInput = {
  name: "pd",
  url: "https://hooks.example.com/edr",
  event_types: ["alert.created"],
  min_severity: "high",
  enabled: true,
  secret: "sekret",
};

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

describe("webhook API client", () => {
  it("listWebhooks GETs /api/settings/webhooks", async () => {
    const mock = stubFetch([]);
    await listWebhooks();
    const [target, init] = mock.mock.calls[0] as [URL, RequestInit | undefined];
    expect(target.toString()).toContain("/api/settings/webhooks");
    expect(init?.method ?? "GET").toBe("GET");
  });

  it("createWebhook POSTs the body with the CSRF header", async () => {
    sessionStorage.setItem("edr_csrf_token", "csrf-token-123");
    const mock = stubFetch({ id: 1 });
    await createWebhook(input);
    const [target, init] = mock.mock.calls[0] as [URL, RequestInit & { headers: Record<string, string> }];
    expect(target.toString()).toContain("/api/settings/webhooks");
    expect(init.method).toBe("POST");
    const expectedCsrf: Record<string, string> = {};
    attachCsrfHeader(expectedCsrf, "POST");
    expect(init.headers).toMatchObject(expectedCsrf);
    expect(JSON.parse(init.body as string)).toMatchObject({ name: "pd", secret: "sekret" });
  });

  it("updateWebhook PUTs to the id path", async () => {
    const mock = stubFetch({ id: 7 });
    await updateWebhook(7, input);
    const [target, init] = mock.mock.calls[0] as [URL, RequestInit | undefined];
    expect(target.toString()).toContain("/api/settings/webhooks/7");
    expect(init?.method).toBe("PUT");
  });

  it("deleteWebhook DELETEs the id path", async () => {
    const mock = stubFetch({}, 204);
    await deleteWebhook(7);
    const [target, init] = mock.mock.calls[0] as [URL, RequestInit | undefined];
    expect(target.toString()).toContain("/api/settings/webhooks/7");
    expect(init?.method).toBe("DELETE");
  });

  it("listWebhookDeliveries GETs the deliveries subpath", async () => {
    const mock = stubFetch([]);
    await listWebhookDeliveries(7);
    const [target, init] = mock.mock.calls[0] as [URL, RequestInit | undefined];
    expect(target.toString()).toContain("/api/settings/webhooks/7/deliveries");
    expect(init?.method ?? "GET").toBe("GET");
  });

  it("testWebhook POSTs the test subpath", async () => {
    const mock = stubFetch({ ok: true, status_code: 200 });
    const out = await testWebhook(7);
    const [target, init] = mock.mock.calls[0] as [URL, RequestInit | undefined];
    expect(target.toString()).toContain("/api/settings/webhooks/7/test");
    expect(init?.method).toBe("POST");
    expect(out.ok).toBe(true);
  });
});
