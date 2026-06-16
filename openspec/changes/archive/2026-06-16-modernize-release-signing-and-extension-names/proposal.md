# Modernize release signing to cosign bundles and give the extensions recognizable names

## Why

Two independent install-path defects, both surfacing only on the manual (non-MDM) flow:

- **Signing (issue #369).** The release pipeline signs every blob artifact with the legacy cosign "two files per artifact" pattern (`cosign sign-blob --output-signature <file>.sig --output-certificate <file>.pem`), and the docs tell verifiers to run `cosign verify-blob --certificate <file>.pem --signature <file>.sig ...`. cosign v2.6+ deprecates `--certificate` and `--signature`; v3 removes the matching `--output-*` flags entirely. A pilot on a current cosign sees deprecation warnings, and the recipe is on a removal path.
- **Display names (issue #370).** Both system extensions ship with the Xcode target defaults `CFBundleDisplayName = extension` and `networkextension`, so macOS System Settings lists them as "extension" and "networkextension". During a manual install the operator cannot tell which Full Disk Access entry belongs to Fleet EDR; until they grant FDA to the entry labeled "extension", the Endpoint Security extension boot-loops with `Failed to create ES client: 4` (`ERR_NOT_PERMITTED`).

## What changes

- **Bundle signing (cosign v3).** Bump the blob-signing job to cosign v3 and emit a single Sigstore bundle (`<file>.sigstore.json`, media type `application/vnd.dev.sigstore.bundle.v0.3+json`) per artifact via `cosign sign-blob --bundle` (the v3 default format, so no `--new-bundle-format` flag). The legacy `.sig`/`.pem` pair is dropped from v0.2.0 onward; v0.1.1 and earlier keep their already-published files on the release page and stay verifiable, but the docs no longer carry the legacy recipe. The docs document only the v3 bundle verify recipe (`cosign verify-blob --bundle <file>.sigstore.json ...`), with no backward-compat notes: anyone needing the old command can recover it from git history.
- **Full v3 move for the image jobs.** Bump the two GHCR image-signing jobs to cosign v3 as well, adopting v3 defaults (image signatures and SBOM attestations stored as OCI 1.1 referring artifacts). No freeze flag: this is a deliberate full move, validated by cutting an RC tag. Doc/comment claims are corrected to v3 (notably: SBOM attestations are resolved with `cosign verify-attestation --type spdxjson` / `cosign download attestation`, NOT the deprecated `cosign download sbom`, which only reads `attach sbom` attachments).
- **Recognizable display names.** Set `INFOPLIST_KEY_CFBundleDisplayName` to "Fleet EDR Security Extension" and "Fleet EDR Network Extension" on the two extension targets, and add a build-time guard in `packaging/pkg/build.sh` that fails the pkg build if either staged extension carries the wrong display name. The manual-install doc Step 6 is updated to name the new entry instead of the literal "extension".

### Not in this change

- Re-signing or relabeling v0.1.1 artifacts: the bundle format cannot be retrofitted onto a published release. Those artifacts stay verifiable with the old command, which is recoverable from git history; the current docs are v3-only.
- Any agent, server, or event-wire change: this is release-pipeline + Xcode-build packaging only.
