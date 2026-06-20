# Release checklist

The steps to cut a tagged release (`vX.Y.Z`). The signed/notarized pkg, the mobileconfig profiles, the SBOMs, and the cosign attestations are produced automatically by `.github/workflows/release.yml` on the `v*` tag push; this checklist covers the human-ordered work that has to happen first, plus the OpenSpec archive step that the release gate enforces.

## 1. Archive all completed OpenSpec changes

OpenSpec deltas are NOT archived per-merge (see CLAUDE.md). They accumulate in `openspec/changes/<name>/` across the release cycle and are archived in one batch here, so the canonical `openspec/specs/**` tree moves only at release boundaries and is reviewed as a single diff.

On a release-prep branch off `main`:

1. List the pending changes: `ls -1 openspec/changes/ | grep -v '^archive$'`.
2. For each completed change, run `openspec archive <name> -y` (NO `--skip-specs`). This merges the delta into `openspec/specs/**` and moves the folder to `openspec/changes/archive/<date>-<name>/`. Use `--skip-specs` ONLY for a tooling/doc-only change that shipped no spec delta.
3. If a merged change is genuinely deferred to a later release (incomplete, intentionally held), it must not ship its delta into the canonical specs yet. Decide explicitly: either finish + archive it, or back its delta out of this release. The gate (step 4) does not let an un-archived change ride silently into a release.
4. Verify the canonical tree is well-formed and fully traced after archiving:
   - `openspec validate --all --strict`
   - `go run ./tools/spectrace check --strict`
5. Confirm nothing un-archived remains: `ls -1 openspec/changes/ | grep -v '^archive$'` prints nothing.

Open the release-prep PR, get it reviewed (the archive is where editing `openspec/specs/**` is expected and legitimate, unlike on a feature branch), and merge it to `main` before tagging.

> Note on removed requirements: a change that retires a requirement (a `## REMOVED Requirements` delta) does not need to be archived early to keep CI green. `spectrace check --strict` exempts canonical scenarios whose requirement an in-flight delta marks `## REMOVED`, so the requirement's tests can be deleted on the merging PR and the gate stays honest until this archive step finalizes the removal.

## 2. Pre-tag verification

- `task lint:go`, `task lint:nilaway`, `task lint:dashes` clean.
- `task test:go:server` and `task test:go:agent` green (CI mirrors these; a local run avoids a failed release build).
- Agent/extension changes touching ESF, XPC, or the event wire format have been exercised on a live macOS VM since the last release (the system/VM layer; see `docs/testing-strategy.md`).
- `CHANGELOG` / release notes drafted.

## 3. Tag and let the release workflow run

1. Create the annotated tag on the merged release-prep commit: `git tag -a vX.Y.Z -m "vX.Y.Z"` and push it.
2. The `v*` push triggers `.github/workflows/release.yml`. Its `openspec-archived` job runs first; every publishing job (`macos-pkg`, `docker-server`, `docker-demo-seed`) depends on it via `needs:`, so the release fails before any signing if `openspec/changes/` still holds a non-archive folder. That is the automated backstop for the "nothing un-archived remains" check (section 1, item 5).
3. After the workflow succeeds, verify the GitHub Release carries the signed pkg, the two mobileconfig profiles, the SBOMs, the `SHA256SUMS`, and the cosign bundles; spot-check `cosign verify-attestation` per the signing docs.

## 4. Dry-run option

To rehearse the build/sign path from a topic branch without cutting a tag, trigger `release.yml` via `workflow_dispatch`; the run sets `--dry-run` and skips signing/notarization. The `openspec-archived` gate is advisory on a dry-run (it reports but does not fail), since a topic branch legitimately carries in-flight changes.
