import { defineConfig, devices } from "@playwright/test";
import { assertLaneEnv } from "./fixtures/db";

// Playwright config for the EDR's E2E suite.
//
// `webServer.command` boots the dev server pointed at the local dex
// (started via `task qa:up`) so both break-glass (WebAuthn + virtual
// authenticator) and OIDC tests run against one process. The
// reuseExistingServer flag lets an operator iterate on tests against
// a server they started manually (`task dev:server:qa-oidc`) without
// each `playwright test` invocation racing a port-bind.
//
// Each test resets its own DB state via fixtures/db.ts so tests stay
// independent (Playwright can shuffle them in any order on retries
// or parallel workers).

// Lane A's dev server by default. Overridable because this repository is worked as two worktrees sharing one machine: lane B runs
// on 8089, and a hardcoded 8088 there either drives the OTHER lane's server or races its port bind, so the suite was simply not
// runnable from lane B. E2E_PORT=8089 points it at the lane the developer is actually in.
const PORT = Number(process.env.E2E_PORT ?? 8088);

// The schema the lane owns, derived the same way fixtures/db.ts derives it so the spawned server and the suite's own connections
// cannot disagree about which lane they are in.
const SCHEMA = process.env.E2E_DB ?? "edr";

// Checked here as well as in fixtures/db.ts so a half-configured lane fails before Playwright boots a server or a browser, rather
// than at the first test that happens to touch the database.
assertLaneEnv();

export default defineConfig({
  testDir: "./tests",
  fullyParallel: false, // tests share one DB; serial keeps the fixtures honest
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1, // shared DB; one worker
  // 90s rather than Playwright's 30s default, because a sign-in can legitimately have to WAIT.
  //
  // `/admin/break-glass/setup` is capped at 5 submissions per minute globally and one sign-in spends two, so a phase signing in
  // more often than the bucket refills makes a rate-limited attempt an expected path rather than an exceptional one. The helper
  // waits it out, bounded at six refill intervals of 13s, and hooks share the test's budget, so the default 30s would fail the
  // test on the timeout instead of letting it recover. 90s covers the bounded sequence with room for the ceremony itself.
  //
  // The cost is that a genuinely hung test now takes 90s to fail rather than 30s. Worth it against specs failing spuriously on
  // arithmetic, and temporary: #912 forges the session for the specs that only need to be signed in, which removes the waiting
  // and lets this come back down.
  timeout: 90_000,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: `https://localhost:${PORT}`,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    // The dev cert is self-signed (openssl fallback when mkcert isn't installed,
    // typical in CI). Without ignoreHTTPSErrors, every page.goto raises a TLS
    // verification error. Production deployments use a real cert chain so this
    // is a dev-only relaxation, not a posture change (issue #140).
    ignoreHTTPSErrors: true,
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  // Spawning works in EITHER lane (issue #826). It used to be lane A only: the command is `task dev:server:qa-oidc`, whose env
  // block hardcodes 8088 and the `edr` schema, so under a lane override it booted lane A's server and then probed lane B's port
  // until the timeout, reporting "webServer was not able to start" with nothing pointing at the cause. #824 skipped the spawn
  // entirely rather than fix it, which left `task test:e2e` unusable from a cold lane B.
  //
  // What makes it work is that go-task's `env:` YIELDS to the parent environment, so the values passed below win over the task's
  // own. Verified rather than assumed: with go-task 3.50.0, a task declaring `env: {X: from-taskfile}` prints `from-parent` when
  // the caller exports X. Playwright merges webServer.env over process.env, so PATH and the rest survive.
  //
  // The dex half is what made this awkward, and it is settled in config/dex/dev-config.yaml: the `edr-qa` client now lists both
  // lanes' callback URLs, so the derived redirect is accepted whichever lane seeded it.
  webServer: {
    // Boot the dev server with OIDC pointed at the local dex. Both
    // break-glass and OIDC flows route through this one instance.
    // Probe /readyz instead of /livez: the spec + docs/install-server.md
    // + docs/operations.md treat /readyz as the readiness signal
    // (returns 200 when the DB ping succeeds). /livez only proves
    // the process is up; tests that hit DB-backed endpoints need
    // the readiness guarantee.
    command: "cd ../.. && task dev:server:qa-oidc",
    // Every value the task hardcodes to lane A, restated for whichever lane the suite was pointed at. The migrate and seed
    // steps that run before the server read EDR_DSN too, so they land in the same schema the suite will reset.
    env: {
      EDR_LISTEN_ADDR: `0.0.0.0:${PORT}`,
      EDR_DSN: `root:@tcp(127.0.0.1:33306)/${SCHEMA}?parseTime=true`,
      // Deferring to an exported value preserves the one escape hatch the task already offered: its own EDR_CLICKHOUSE_DSN is
      // written as a go-task template with a default, so a developer pointing at another ClickHouse keeps doing so. The other
      // four are hardcoded in the task, so there is no existing override to respect.
      EDR_CLICKHOUSE_DSN: process.env.EDR_CLICKHOUSE_DSN ?? `clickhouse://default:@127.0.0.1:19000/${SCHEMA}`,
      EDR_BREAKGLASS_RP_ORIGINS: `https://localhost:${PORT}`,
      EDR_DEMO_OIDC_EXTERNAL_URL: `https://localhost:${PORT}`,
    },
    url: `https://localhost:${PORT}/readyz`,
    // The webServer probe ignores TLS-cert errors so a self-signed dev cert
    // doesn't kill the probe before the server has a chance to start. Same
    // rationale as `use.ignoreHTTPSErrors` above (issue #140).
    ignoreHTTPSErrors: true,
    // The default `!CI` reuse rule prevents the coverage runner from
    // attaching to a server it just booted (CI is set in GH Actions,
    // so Playwright would normally spawn its own `task dev:server:
    // qa-oidc`, bypassing the instrumented binary). E2E_REUSE_SERVER=1
    // is the opt-in that lets `task test:e2e:coverage` start the
    // covered server in the foreground and then ask Playwright to
    // reuse it. Other CI contexts (e.g. a future hosted runner that
    // boots its own webServer) leave the env unset and get the
    // standard !CI behavior.
    reuseExistingServer: !process.env.CI || process.env.E2E_REUSE_SERVER === "1",
    timeout: 60_000,
    stderr: "pipe",
    stdout: "pipe",
  },
});
