# L6 detection efficacy harness

Walks an in-tree attack-scenario corpus + an ambient-noise corpus through the real EDR server (composed via `test/integration.Setup`) and asserts two aggregate gates per [`testing-strategy.md`](../../docs/testing-strategy.md):

- Detection rate >= 95% across all attack scenarios.
- False-positive rate <= 1% across all noise scenarios.

A run is one `go test -tags integration ./test/efficacy/...` invocation. Single Stack, real MySQL, real detection engine. No agent in the loop -- each scenario POSTs its event timeline directly to `/api/events` via the M3 fakeagent's `PostDirect` helper. The L3 layer (M4) already covers the queue + uploader path; L6's signal is specifically about rule firings.

## Directory layout

    test/efficacy/
      README.md                    -- this file
      efficacy_test.go             -- the L6 runner
      corpus/                      -- attack scenarios, one dir per MITRE technique
        T<technique-id>-<slug>/
          scenario.yaml            -- fakeagent timeline (events that should trip the rule)
          expected.yaml            -- rule_id + severity + within_seconds SLA
          attack.sh                -- VM driver stub; M11 wires the L5 runner here
      noise/                       -- ambient-noise scenarios, flat *.yaml + one expected.yaml
        developer-workstation.yaml
        homebrew-update.yaml
        expected.yaml              -- one file applies to all noise; rules: [] (zero alerts expected)

## Scenario YAML format

`scenario.yaml` is the standard `test/fakeagent` Scenario shape: a host descriptor + a timeline of typed events (fork / exec / open / exit / network_connect / dns_query / snapshot_heartbeat). The exact field set is documented in `test/fakeagent/fakeagent.go`'s `Event` struct.

`expected.yaml` is small and intentionally narrow:

    scenario_id: T1555.001-keychain-dump
    mitre: T1555.001
    within_seconds: 30
    rules:
      - rule_id: credential_keychain_dump
        severity: high
        expect: alert

For noise scenarios `rules:` is `[]` -- the runner asserts no alerts fire on the host at all.

## Adding a new technique scenario

1. Pick the MITRE technique ID (e.g. `T1027.005` for "Indicator Removal from Tools"). Create `corpus/T1027.005-<slug>/`.
2. Author `scenario.yaml` with the event timeline that trips the rule. Cross-check against the rule's positive fixture under `server/rules/internal/catalog/fixtures/<rule-id>/positive_*.json` -- each rule already has a "this is the event shape that should fire me" spec there; the scenario.yaml is the fakeagent-flavoured equivalent.
3. Author `expected.yaml`: scenario_id, mitre, within_seconds, the single expected rule_id + severity.
4. Stub `attack.sh` with a `#!/usr/bin/env bash` header + a comment block describing the real-VM equivalent. M11 will wire the L5 driver to actually run these on edr-qa; for now the file documents intent.
5. Run `CGO_ENABLED=0 go test -tags integration ./test/efficacy/...` to verify the scenario passes the L6 gate.

## Adding a new noise scenario

1. Add a `noise/<descriptive>.yaml` -- standard fakeagent Scenario shape.
2. Use a unique host_id (different from the corpus host ids; the `BBBB*` prefix is reserved for noise).
3. Run the suite; the scenario should produce zero alerts. A FP here is a sign that one of the catalog rules has gotten greedy and is matching legitimate user activity -- file an issue against the offending rule.

## CI

`.github/workflows/efficacy.yml` runs the L6 suite nightly on `main` via cron + on `workflow_dispatch`. The detection-efficacy gate fires the same hard pass / fail signal CI uses for unit tests. Per-PR runs are NOT wired because the corpus is intentionally extensible and the rule catalog matures faster than a per-PR cycle can absorb regressions cleanly; L0--L4 catch per-PR drift and L6 catches "the catalog as a whole regressed."

## Why no VM here

The L5 layer (M9 driver + M11 self-hosted runner) covers the real-VM flavour: same `attack.sh` files, same `expected.yaml`, but driven against a SIP-on macOS host. L6 is the synthetic-events lane that proves the catalog rules behave correctly given the canonical event sequences -- it runs in seconds, not the 30 minutes the L5 lane takes per scenario, and it runs nightly rather than on RC tags. Same corpus, two delivery mechanisms.
