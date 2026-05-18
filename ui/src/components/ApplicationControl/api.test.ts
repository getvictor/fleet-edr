import { describe, it, expect, vi, afterEach } from "vitest";
import {
  bulkUpsertAppControlRules,
  createAppControlRule,
  deleteAppControlRule,
  listAppControlPolicies,
  getAppControlPolicy,
  updateAppControlRule,
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

// updateAppControlRule + deleteAppControlRule share patchAppControlEndpoint, so the test pairs cover the auth + typed-error
// machinery with two different verbs (PATCH happy + DELETE happy + one typed 4xx per verb + one 401 per verb).

describe("updateAppControlRule", () => {
  it("returns the updated rule body on the happy path", async () => {
    setCsrfToken("FAKE_CSRF_TOKEN");
    const fakeRule = { id: 7, enabled: false, severity: "high" };
    const fetchMock = mockFetch(fakeRule, 200);
    const got = await updateAppControlRule(7, { enabled: false, reason: "test" });
    expect(got).toEqual(fakeRule);
    expect(fetchMock).toHaveBeenCalledOnce();
    const [, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(init.method).toBe("PATCH");
  });

  it("surfaces a typed AppControlApiError for application_control.rule_not_found 404", async () => {
    setCsrfToken("FAKE_CSRF_TOKEN");
    mockFetch({ error: "application_control.rule_not_found", message: "rule not found" }, 404);
    try {
      await updateAppControlRule(99, { enabled: true, reason: "x" });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AppControlApiError);
      if (err instanceof AppControlApiError) {
        expect(err.code).toBe("application_control.rule_not_found");
        expect(err.status).toBe(404);
      }
    }
  });

  it("throws Unauthorized401Error on a 401", async () => {
    setCsrfToken("FAKE_CSRF_TOKEN");
    mockFetch({}, 401);
    await expect(
      updateAppControlRule(1, { enabled: false, reason: "x" }),
    ).rejects.toBeInstanceOf(Unauthorized401Error);
  });

  it("falls through to plain API error when the 4xx body lacks the typed envelope", async () => {
    setCsrfToken("FAKE_CSRF_TOKEN");
    mockFetch({ something: "else" }, 400);
    await expect(
      updateAppControlRule(1, { reason: "x" }),
    ).rejects.toThrow(/API error/);
  });
});

describe("deleteAppControlRule", () => {
  it("resolves on 204 No Content with no body", async () => {
    setCsrfToken("FAKE_CSRF_TOKEN");
    const fetchMock = mockFetch(undefined, 204);
    await deleteAppControlRule(7, { reason: "test" });
    expect(fetchMock).toHaveBeenCalledOnce();
    const [, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(init.method).toBe("DELETE");
  });

  it("surfaces a typed AppControlApiError when the rule is gone", async () => {
    setCsrfToken("FAKE_CSRF_TOKEN");
    mockFetch({ error: "application_control.rule_not_found", message: "rule not found" }, 404);
    try {
      await deleteAppControlRule(99, { reason: "x" });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AppControlApiError);
      if (err instanceof AppControlApiError) {
        expect(err.code).toBe("application_control.rule_not_found");
      }
    }
  });

  it("throws Unauthorized401Error on a 401", async () => {
    setCsrfToken("FAKE_CSRF_TOKEN");
    mockFetch({}, 401);
    await expect(
      deleteAppControlRule(1, { reason: "x" }),
    ).rejects.toBeInstanceOf(Unauthorized401Error);
  });
});

describe("bulkUpsertAppControlRules", () => {
  it("returns inserted/updated counts and rule rows on the happy path", async () => {
    setCsrfToken("FAKE_CSRF_TOKEN");
    const fakeResult = {
      inserted: 2,
      updated: 1,
      rules: [
        { id: 1, identifier: "a".repeat(64) },
        { id: 2, identifier: "b".repeat(64) },
        { id: 3, identifier: "EQHXZ8M8AV" },
      ],
    };
    const fetchMock = mockFetch(fakeResult, 200);
    const got = await bulkUpsertAppControlRules(7, {
      rules: [
        { rule_type: "BINARY", identifier: "a".repeat(64) },
        { rule_type: "BINARY", identifier: "b".repeat(64) },
        { rule_type: "TEAMID", identifier: "EQHXZ8M8AV" },
      ],
      reason: "import from spreadsheet",
    });
    expect(got.inserted).toBe(2);
    expect(got.updated).toBe(1);
    expect(got.rules).toHaveLength(3);
    expect(fetchMock).toHaveBeenCalledOnce();
    const [target, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(target.pathname).toMatch(/policies\/7\/rules:bulkUpsert$/);
    expect(init.method).toBe("POST");
  });

  it("surfaces typed AppControlApiError when the server rejects an item", async () => {
    setCsrfToken("FAKE_CSRF_TOKEN");
    mockFetch(
      {
        error: "application_control.invalid_rule",
        message: "bulk item 1: identifier failed validation",
      },
      400,
    );
    try {
      await bulkUpsertAppControlRules(1, {
        rules: [
          { rule_type: "BINARY", identifier: "not-hex" },
        ],
        reason: "x",
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AppControlApiError);
      if (err instanceof AppControlApiError) {
        expect(err.code).toBe("application_control.invalid_rule");
        expect(err.message).toMatch(/bulk item 1/);
      }
    }
  });

  it("throws Unauthorized401Error on a 401", async () => {
    setCsrfToken("FAKE_CSRF_TOKEN");
    mockFetch({}, 401);
    await expect(
      bulkUpsertAppControlRules(1, { rules: [], reason: "x" }),
    ).rejects.toBeInstanceOf(Unauthorized401Error);
  });
});
