# Release checklist

The steps to cut a tagged release. The signed/notarized pkg, the mobileconfig profiles, the SBOMs, and the cosign attestations are produced automatically by `.github/workflows/release.yml` on a `v*` tag push; this checklist covers the human-ordered work that has to happen first, plus the validation gates that a release candidate must clear before it is promoted to a stable tag.

The flow is built around a release-candidate (RC) loop: cut `vX.Y.Z-rc.N`, run the candidate-only validation against it, and only then promote to the stable `vX.Y.Z` tag. An RC tag is signed like a stable tag but does NOT advance the `:latest` server image (`docs/README.md`), so it is safe to validate against real infrastructure. If validation surfaces a blocker, fix it on `main` and cut `rc.N+1`; repeat until an RC is clean.

## 1. Archive all completed OpenSpec changes

OpenSpec deltas are NOT archived per-merge (see CLAUDE.md). They accumulate in `openspec/changes/<name>/` across the release cycle and are archived in one batch here, so the canonical `openspec/specs/**` tree moves only at release boundaries and is reviewed as a single diff.

On a release-prep branch off `main`:

1. List the pending changes: `ls -1 openspec/changes/ | grep -v '^archive$'`.
2. For each completed change, run `openspec archive <name> -y` (NO `--skip-specs`). This merges the delta into `openspec/specs/**` and moves the folder to `openspec/changes/archive/<date>-<name>/`. Use `--skip-specs` ONLY for a tooling/doc-only change that shipped no spec delta.
3. If a merged change is genuinely deferred to a later release (incomplete, intentionally held), it must not ship its delta into the canonical specs yet. Decide explicitly: either finish + archive it, or back its delta out of this release. The release gate (`openspec-archived` in `release.yml`) does not let an un-archived change ride silently into a release.
4. Verify the canonical tree is well-formed and fully traced after archiving:
   - `openspec validate --all --strict`
   - `go run ./tools/spectrace check --strict`
5. Confirm nothing un-archived remains: `ls -1 openspec/changes/ | grep -v '^archive$'` prints nothing.

> Note on removed requirements: a change that retires a requirement (a `## REMOVED Requirements` delta) does not need to be archived early to keep CI green. `spectrace check --strict` exempts canonical scenarios whose requirement an in-flight delta marks `## REMOVED`, so the requirement's tests can be deleted on the merging PR and the gate stays honest until this archive step finalizes the removal.

## 2. Prepare and land the release-prep PR

On the same release-prep branch, alongside the archive from step 1:

1. Draft the changelog: move the `CHANGELOG.md` `[Unreleased]` items into a new versioned section (`## [X.Y.Z] (YYYY-MM-DD)`), grouped under Added / Changed / Fixed / Removed, and write the release-notes highlights.
2. Bump the pinned release tag in the operator deploy docs so the copy-paste deploy snippets stay current. Run `tools/bump-doc-versions.sh vX.Y.Z`: it rewrites every pinned version token in `docs/quickstart-vm.md`, `docs/install-server.md`, `docs/install-agent-manual.md`, `docs/mdm-deployment.md`, `docs/fleet-deployment.md`, and `bootstrap.sh`, printing every change for review. These literals are intentionally pinned (a pilot must deploy a known signed tag), so they do not float. `README.md` is deliberately NOT in that set: it is the evergreen landing page and stays version-free (it shows `EDR_VERSION=latest` and routes to the quickstart for the production pin). The demo (`docker-compose.demo.yml`) defaults to `latest` and is NOT bumped. The full model is in [`doc-versioning.md`](doc-versioning.md); the `docs-version-pinned` job in `release.yml` re-checks this on the stable tag and fails the release if any snippet is stale.
3. Pass the automated gates locally (they mirror CI; a local run avoids a failed release build):
   - `task lint:go`, `task lint:nilaway`, `task lint:dashes` clean.
   - `task test:go:server` and `task test:go:agent` green.
   - The cross-context integration and browser-with-fake-agent suites green.
4. Open the release-prep PR and get it reviewed. The archive is where editing `openspec/specs/**` is expected and legitimate, unlike on a feature branch, so this is the diff a reviewer scrutinizes.
5. Merge to `main`. Everything downstream tags off the merged commit.

## 3. Cut a release candidate

1. Create the annotated RC tag on the merged commit: `git tag -a vX.Y.Z-rc.N -m "vX.Y.Z-rc.N"` and push it.
2. The `v*` push triggers `release.yml`. Its `openspec-archived` job runs first; every publishing job (`macos-pkg`, `docker-server`, `docker-demo-seed`) depends on it via `needs:`, so the release fails before any signing if `openspec/changes/` still holds a non-archive folder. That is the automated backstop for the "nothing un-archived remains" check (step 1, item 5).
3. The RC is signed and published but does not advance `:latest`. Use it for the validation in steps 4 through 6.

## 4. Run candidate-only validation against the RC

These layers do not run per-PR (`docs/testing-strategy.md`); the RC is where they gate.

- The macOS VM end-to-end run: real Swift extensions + real agent + real server on a SIP-enabled, Gatekeeper-enabled VM. Any agent/extension change touching ESF, XPC, or the event wire format MUST be exercised here since the last release.
- The detection-efficacy run: the MITRE-aligned attack corpus, asserting each shipped rule fires within its SLA (detection rate gate) and the noise corpus stays clean (false-positive gate).

## 5. Manual UI review

Drive the built UI from the RC server image and walk the core operator journeys to catch rendering and interaction regressions the automated suites do not assert: sign-in, host list, process tree, alert detail, and policy / app-control editing.

## 6. Deploy the RC to the dogfood server and enroll a real device

Roll the candidate server image onto the live dogfood deployment, enroll an actual Mac, and confirm on real hardware: enrollment succeeds, telemetry flows, and at least one real detection fires end to end. This is the last gate that exercises the full product the way a pilot customer would.

If any of steps 4 through 6 surfaces a blocker, fix it on `main` and return to step 3 with `rc.N+1`. Only a clean RC is promoted.

## 7. Promote to a stable tag

1. Create the annotated stable tag on the same commit the clean RC was built from: `git tag -a vX.Y.Z -m "vX.Y.Z"` and push it.
2. `release.yml` re-runs and, because this is a non-`-rc` tag, advances `:latest` and produces the final signed pkg, the two mobileconfig profiles, the SBOMs, the `SHA256SUMS`, and the cosign bundles.

## 8. Verify the published release

Run the `verify-release` skill against the stable tag. It confirms the GitHub Release carries every expected artifact and that each one verifies: asset completeness, checksums, per-artifact Sigstore bundles, the server image signature (plus the `:latest` digest match for a stable tag), the build-provenance attestations, and the macOS Gatekeeper checks on the pkg. Any failure means the release is not safe to announce.

## Dry-run option

To rehearse the build/sign path from a topic branch without cutting a tag, trigger `release.yml` via `workflow_dispatch`; the run sets `--dry-run` and skips signing/notarization. The `openspec-archived` gate is advisory on a dry-run (it reports but does not fail), since a topic branch legitimately carries in-flight changes.
