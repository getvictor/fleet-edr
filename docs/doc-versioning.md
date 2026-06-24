# Documentation versioning

How Fleet EDR keeps its docs matched to releases. The short version: `main` documents the development build, and the "current" docs a reader should follow are the docs at the latest stable git tag.

## The model

The product ships as discrete signed releases, but the docs live in the same repo and move continuously on `main`. Those two cadences drift unless we are explicit about what each doc tree represents:

- **`main` docs describe `main`** (the next, unreleased version). A behavior change updates the docs in the same PR that makes the change (docs as code), so the docs on `main` never lag the code on `main`.
- **The "current" docs are the docs at the latest stable git tag.** Because the docs are versioned with the code, browsing `docs/` at tag `vX.Y.Z` shows exactly the docs for that release. An operator running `vX.Y.Z` reads the `vX.Y.Z`-tagged docs and sees instructions that match the build they run.

We do not try to make a single doc tree correct for both the released version and the development version at once. That is impossible, and chasing it with conditional prose is what produces drift. Versioning the docs with the code is the resolution.

## README is evergreen

`README.md` is the repository landing page. GitHub renders it from the default branch for every visitor regardless of which version they will run, so it must never pin a version. It describes what the product is, routes to the demo, and links to the deploy docs. The version-pinned, copy-paste deploy command lives in [`quickstart-vm.md`](quickstart-vm.md), which is versioned with the release; the README shows `EDR_VERSION=latest` and points there for the production pin.

## The demo floats; deploy snippets are pinned

These two getting-started paths want opposite treatments:

- **The demo floats to `:latest`.** `docker-compose.demo.yml` defaults its images to the newest published tag so the demo always shows the current product. It auto-advances when a stable release moves `:latest`, and is never bumped by hand.
- **Deploy snippets are pinned to a signed tag.** A pilot must deploy a known, reproducible, signed version, so the deploy docs pin an explicit `vX.Y.Z`. These literals are bumped at release time, never floated. The bump is mechanical: `tools/bump-doc-versions.sh vX.Y.Z` (see [`release-checklist.md`](release-checklist.md)).

The files that carry a pinned deploy tag are `docs/quickstart-vm.md`, `docs/install-server.md`, `docs/install-agent-manual.md`, `docs/mdm-deployment.md`, `docs/fleet-deployment.md`, and `bootstrap.sh`. They reference only the current release tag; historical or upgrade-path version mentions belong in [`../CHANGELOG.md`](../CHANGELOG.md), not in these files, because the bump rewrites every version token in them wholesale.

## Two gates back this

- **Docs stay in step with code.** `Docs sync` (`.github/workflows/docs-sync.yml`), a sibling of the OpenSpec sync gate, fails a PR that changes a user-facing surface (the React UI, an HTTP request handler, or a detection rule) without also touching `docs/` or `CHANGELOG.md`. Like the OpenSpec gate it fires on path, so it has false positives (an internal refactor, a non-visible UI tweak). The opt-out is an auditable assertion that the change is not user-facing: the `no-docs-change` label or a `[no-docs-change]` tag in the PR title. It is never a way to skip documenting a real user-facing change.
- **Pinned tags stay current.** The `docs-version-pinned` job in `release.yml` runs on a stable `v*` tag and fails the release if any pinned deploy snippet does not equal the tag being published, so a forgotten bump cannot publish. It is a no-op on rc tags, because the docs are bumped to the stable tag in the release-prep PR before the rc is cut.
