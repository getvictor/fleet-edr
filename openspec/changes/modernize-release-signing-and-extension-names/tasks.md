# Modernize release signing and extension names: tasks

## 1. Bundle signing (issue #369)

- [x] `release.yml`: bump all three `cosign-installer` pins from v2.5.3 to v3.1.1.
- [x] `release.yml` blob-signing step: `cosign sign-blob --bundle "${f}.sigstore.json"` per artifact (pkg, both mobileconfigs, SHA256SUMS, both SBOMs); upload the `.sigstore.json` bundles and drop the `.sig`/`.pem` uploads.
- [x] `release.yml`: rewrite the signing comment block to describe the bundle format and the `cosign verify-blob --bundle ...` recipe.

## 2. Full v3 move for image jobs (issue #369)

- [x] `release.yml`: leave `cosign sign` / `cosign attest` on the GHCR server + demo-seed images using v3 defaults (OCI 1.1 referring-artifact storage); no `--registry-referrers-mode` freeze.
- [x] `release.yml`: correct the image comments: signatures stored as OCI 1.1 referring artifacts; SBOM attestations resolved via `cosign verify-attestation --type spdxjson` / `cosign download attestation`, not the deprecated `cosign download sbom`.

## 3. Recognizable display names (issue #370)

- [x] `extension/edr/edr.xcodeproj/project.pbxproj`: `INFOPLIST_KEY_CFBundleDisplayName = "Fleet EDR Security Extension"` (Debug+Release) and `"Fleet EDR Network Extension"` (Debug+Release).
- [x] `packaging/pkg/build.sh`: fail the build (exit 10 / 11) if a staged extension's `CFBundleDisplayName` is not the expected Fleet EDR name; runs on dry-run and release paths.

## 4. Docs

- [x] `docs/install-agent-manual.md`: rewrite the "verify the Sigstore signature" section to the `--bundle` recipe (v0.2.0 example), with a legacy `.sig`/`.pem` note for v0.1.1 and earlier.
- [x] `docs/install-agent-manual.md` Step 6 + troubleshooting: name the new "Fleet EDR Security Extension" / "Fleet EDR Network Extension" entries.
- [x] `docs/best-practices.md`: update the supply-chain bullet to cosign v3 bundles + OCI 1.1 image storage (was "tracked as a drop-in pin upgrade").

## 5. Spec

- [x] `release-packaging`: ADDED "Release artifacts carry a verifiable Sigstore signature" and "System extensions present recognizable display names", with `# spec:` markers in `release.yml` and `packaging/pkg/build.sh`.

## 6. Verification

- [x] Local cosign v3 blob bundle round-trip (`sign-blob --bundle` -> `verify-blob --bundle` -> "Verified OK"; media type `application/vnd.dev.sigstore.bundle.v0.3+json`).
- [x] `xcodebuild` the extensions and confirm the built bundles' `CFBundleDisplayName` reads "Fleet EDR Security Extension" / "Fleet EDR Network Extension".
- [x] `actionlint .github/workflows/release.yml`; `shellcheck packaging/pkg/build.sh`; `openspec validate modernize-release-signing-and-extension-names --strict`; spectrace.
- [ ] Cut an RC tag to verify the keyless bundle signing + OCI 1.1 image signing/attestation paths end-to-end (CI-only; cannot run locally).
- [ ] Install the RC pkg on edr-qa and confirm System Settings lists "Fleet EDR Security Extension" / "Fleet EDR Network Extension".
