import { afterEach, describe, expect, it, vi } from "vitest";
import { getHostContainment, listContainment, setHostContainment } from "./api";

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
    clone(): FakeResponse { return fake; },
    json(): Promise<unknown> { return Promise.resolve(body); },
  };
  const mock = vi.fn().mockResolvedValue(fake);
  vi.stubGlobal("fetch", mock);
  return mock;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

describe("containment API client", () => {
  it("reads a host's containment and the list", async () => {
    const one = stubFetch({ host_id: "H 1", contained: true, version: 1, epoch: 1 });
    await getHostContainment("H 1");
    expect((one.mock.calls[0] as [URL])[0].toString()).toContain("/api/hosts/H%201/containment");

    stubFetch({ items: [{ host_id: "H-1", contained: true, version: 1, epoch: 1 }] });
    expect(await listContainment()).toEqual([{ host_id: "H-1", contained: true, version: 1, epoch: 1 }]);
  });

  it("posts the change and returns it", async () => {
    const mock = stubFetch({ state: { host_id: "H-1", contained: true, version: 1, epoch: 1 }, changed: true, command_id: 7 });
    const change = await setHostContainment("H-1", true, "beaconing");
    const [target, init] = mock.mock.calls[0] as [URL, RequestInit];
    expect(target.toString()).toContain("/api/hosts/H-1/containment");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ contained: true, reason: "beaconing" });
    expect(change.command_id).toBe(7);
  });

  it.each([
    ["reason_required", 400, "Give a reason for the audit log."],
    ["reason_too_long", 400, "The reason is too long: keep it to 1024 characters."],
    ["body_too_large", 413, "The reason is too long: keep it to 1024 characters."],
    ["host_not_found", 404, "This host is no longer enrolled, so its containment cannot be changed."],
    ["something_new", 400, "something_new"],
  ])("turns a %s refusal into what the operator can do", async (code, status, message) => {
    stubFetch({ error: code }, status);
    await expect(setHostContainment("H-1", true, "x")).rejects.toThrow(message);
  });
});
