import { describe, it, expect, vi, afterEach } from "vitest";
import {
  createAppControlRule,
  listAppControlPolicies,
  getAppControlPolicy,
  AppControlApiError,
  Unauthorized401Error,
  setCsrfToken,
} from "../../api";

// fetchMock is the per-test wrapper for global.fetch. Vitest's
// vi.spyOn(globalThis, "fetch") keeps the actual implementation
// fenced off the tests so a leaked mock can't bleed into a sibling
// suite.
interface FakeResponse {
  ok: boolean;
  status: number;
  statusText: string;
  clone(): FakeResponse;
  json(): Promise<unknown>;
}

function mockFetch(body: unknown, status = 200): ReturnType<typeof vi.fn> {
  const fake: FakeResponse = {
    ok: status >= 200 && status < 300,
    status,
    statusText: "",
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

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("listAppControlPolicies", () => {
  it("returns the policies array from the wrapped response shape", async () => {
    const fakePolicies = [{ id: 1, name: "Default" }];
    mockFetch({ policies: fakePolicies });
    const got = await listAppControlPolicies();
    expect(got).toEqual(fakePolicies);
  });
});

describe("getAppControlPolicy", () => {
  it("returns the policy body verbatim", async () => {
    const policy = { id: 7, name: "Default", rules: [] };
    mockFetch(policy);
    const got = await getAppControlPolicy(7);
    expect(got).toMatchObject({ id: 7 });
  });
});

describe("createAppControlRule", () => {
  it("returns the created rule on the happy path", async () => {
    setCsrfToken("FAKE_CSRF_TOKEN");
    const rule = { id: 99, rule_type: "BINARY" };
    mockFetch(rule, 201);
    const got = await createAppControlRule(1, {
      rule_type: "BINARY",
      identifier: "a".repeat(64),
      reason: "demo",
    });
    expect(got).toMatchObject({ id: 99 });
  });

  it("throws Unauthorized401Error on a 401", async () => {
    setCsrfToken("FAKE_CSRF_TOKEN");
    mockFetch({}, 401);
    await expect(
      createAppControlRule(1, {
        rule_type: "BINARY",
        identifier: "a".repeat(64),
        reason: "demo",
      }),
    ).rejects.toBeInstanceOf(Unauthorized401Error);
  });

  it("surfaces typed AppControlApiError for application_control.* 4xx codes", async () => {
    setCsrfToken("FAKE_CSRF_TOKEN");
    mockFetch(
      { error: "application_control.duplicate_rule", message: "duplicate" },
      409,
    );
    try {
      await createAppControlRule(1, {
        rule_type: "BINARY",
        identifier: "a".repeat(64),
        reason: "demo",
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AppControlApiError);
      if (err instanceof AppControlApiError) {
        expect(err.code).toBe("application_control.duplicate_rule");
        expect(err.status).toBe(409);
      }
    }
  });

  it("falls through to plain API error when the 4xx body lacks the typed envelope", async () => {
    setCsrfToken("FAKE_CSRF_TOKEN");
    mockFetch({ something: "else" }, 400);
    await expect(
      createAppControlRule(1, {
        rule_type: "BINARY",
        identifier: "a".repeat(64),
        reason: "demo",
      }),
    ).rejects.toThrow(/API error/);
  });
});
