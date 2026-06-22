# Tasks

- [x] Alias the candidate path across the `/private` firmlink in `api.MatchExclusionValue` for `path_glob` / `parent_path_glob` (no glob rewrite).
- [x] Unit table cases for the aliasing (both directions, all three prefixes, non-aliasable path unaffected).
- [x] Rule-layer regression test (`sudoers_tamper`): suppressed when the exclusion and the event path differ only in firmlink form.
- [x] `detectionconfig.Service.RefreshLoop(ctx, interval)` + rules-context `Run(ctx)` + `cmd/fleet-edr-server` wiring; poll `detection_config_meta.version`, reload on change.
- [x] Two-replica convergence integration test (separate Service+Store on one DB).
- [x] OpenSpec delta + spectrace markers for the two new scenarios.
- [ ] Gates: `go build`, `go test`, `task lint:go`, `task lint:dashes`, `tools/spectrace check --strict`, `openspec validate detection-config-hardening --strict`.
- [ ] Archive at release (batched), not per-merge.
