---
name: verify-release
description: Verify a published Fleet EDR GitHub Release carries every expected artifact and that each one's signatures check out. Use after the release workflow finishes (or when the user asks to "verify the release", "check the release artifacts", "verify the signatures for vX.Y.Z").
metadata:
  author: fleet-edr
  version: "1.0"
---

# Verify a published release

The final step of the release checklist: confirm a published GitHub Release (`vX.Y.Z` or `vX.Y.Z-rc.N`) carries every artifact the release workflow is supposed to produce and that each artifact verifies against its checksum, its Sigstore bundle, and its build-provenance attestation. This is read-only verification of an already-published release; it signs nothing and changes nothing.

## Inputs

- `TAG`: the release tag to verify (for example `v0.2.0` or `v0.2.0-rc.1`). Ask the user if it is not supplied.

## Prerequisites

- `gh` authenticated against `getvictor/fleet-edr`.
- `cosign` v3+ (`brew install cosign`).
- `shasum` and `pkgutil` / `xcrun` / `spctl` (stock macOS) for the pkg checks.

Set the constants used throughout. `TAG` must already be set (see Inputs); the signing identity is pinned to THIS tag's `release.yml` run, not any `v*` tag, so an artifact signed for a different release cannot pass even if assets were swapped between releases:

```sh
REPO=getvictor/fleet-edr
IMAGE=ghcr.io/getvictor/fleet-edr-server
ISSUER='https://token.actions.githubusercontent.com'
# Escape regex metacharacters in the tag (the dots), then pin the identity to exactly this tag.
TAG_RE=$(printf '%s' "$TAG" | sed 's/[.[\*^$()+?{|]/\\&/g')
IDENTITY="^https://github\.com/getvictor/fleet-edr/\.github/workflows/release\.yml@refs/tags/${TAG_RE}\$"
```

## Step 1: confirm every expected asset is present

Pull the asset list for the tag and check it against what the workflow uploads. For a tag `vX.Y.Z` the release must carry these 12 assets (six artifacts, each with its `.sigstore.json` bundle):

- `fleet-edr-<TAG>.pkg` (+ `.sigstore.json`)
- `edr-system-extension.mobileconfig` (+ `.sigstore.json`)
- `edr-tcc-fda.mobileconfig` (+ `.sigstore.json`)
- `fleet-edr-<TAG>-sbom.spdx.json` (+ `.sigstore.json`)
- `fleet-edr-<TAG>-sbom.cdx.json` (+ `.sigstore.json`)
- `SHA256SUMS` (+ `.sigstore.json`)

```sh
gh release view "$TAG" --repo "$REPO" --json assets --jq '.assets[].name' | sort
```

Flag any missing or unexpected asset. A missing `.sigstore.json` for any artifact, or a missing SBOM, is a release defect: stop and report it.

## Step 2: download, then establish trust in SHA256SUMS before using it

Order matters: verify the signature on `SHA256SUMS` itself BEFORE trusting it to validate the other downloads, otherwise a tampered `SHA256SUMS` could report a false `OK`.

```sh
workdir=$(mktemp -d) && cd "$workdir"
gh release download "$TAG" --repo "$REPO"

# 1. Trust SHA256SUMS via its own Sigstore bundle FIRST.
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" \
  SHA256SUMS

# 2. Only now use the trusted SHA256SUMS to checksum every other artifact.
#    No --ignore-missing: we downloaded the whole release, so every file listed
#    in SHA256SUMS (pkg, both profiles, both SBOMs) MUST be present. Omitting
#    the flag turns a not-downloaded or misnamed artifact into a hard FAILED
#    instead of a silently skipped line. The extra files on disk (the
#    .sigstore.json bundles and SHA256SUMS itself) are not listed in
#    SHA256SUMS, so `-c` simply does not check them.
shasum -a 256 -c SHA256SUMS
```

Expect `Verified OK` for the bundle, then every `shasum` line `OK`. Any `FAILED` (bad hash) or a `No such file` / missing line is a corrupted, tampered, or absent artifact: stop and report.

## Step 3: verify the Sigstore bundle for each remaining blob artifact

`SHA256SUMS` was already verified in step 2. The same identity/issuer constraints apply to every other blob; loop over the remaining five artifacts:

```sh
for f in fleet-edr-"$TAG".pkg \
         edr-system-extension.mobileconfig \
         edr-tcc-fda.mobileconfig \
         fleet-edr-"$TAG"-sbom.spdx.json \
         fleet-edr-"$TAG"-sbom.cdx.json; do
  echo "== $f =="
  cosign verify-blob \
    --bundle "${f}.sigstore.json" \
    --certificate-identity-regexp "$IDENTITY" \
    --certificate-oidc-issuer "$ISSUER" \
    "$f"
done
```

Expect `Verified OK` for each. The certificate-identity binds the signature to this tag's `release.yml` workflow run, so a stolen Developer ID cert alone cannot forge a passing artifact.

## Step 4: verify the server image signature

The image signature and its SBOM attestation are stored as OCI 1.1 referring artifacts (cosign v3), not as release assets:

```sh
cosign verify "$IMAGE:$TAG" \
  --certificate-identity-regexp "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER"
```

For a stable (non-`-rc`) tag, also confirm `$IMAGE:latest` resolves to the SAME digest as `$IMAGE:$TAG` (the workflow only advances `:latest` on stable tags). Capture both digests and compare them; do not just print them (`brew install crane` if needed):

```sh
latest_digest=$(crane digest "$IMAGE:latest")
tag_digest=$(crane digest "$IMAGE:$TAG")
if [ -n "$tag_digest" ] && [ "$latest_digest" = "$tag_digest" ]; then
  echo "PASS: :latest matches $TAG ($tag_digest)"
else
  echo "FAIL: :latest=$latest_digest does not match $TAG=$tag_digest"
fi
```

Skip this comparison for an `-rc` tag: `:latest` legitimately points at the previous stable release.

## Step 5: verify build-provenance attestations

The workflow attests the pkg, both profiles, both SBOMs, `SHA256SUMS`, and the image via `actions/attest-build-provenance`. Spot-check with the GitHub attestation verifier:

```sh
gh attestation verify fleet-edr-"$TAG".pkg --owner getvictor
gh attestation verify oci://"$IMAGE:$TAG" --owner getvictor
```

Expect a verified provenance summary tying each artifact to the workflow run.

## Step 6: macOS Gatekeeper checks on the pkg (optional but recommended for stable)

Confirms the pkg is Apple-signed, notarized, and stapled, independent of Sigstore:

```sh
pkgutil --check-signature fleet-edr-"$TAG".pkg   # signed by Apple-issued Developer ID + notarized
xcrun stapler validate fleet-edr-"$TAG".pkg      # stapled ticket present (works offline)
spctl -a -v --type install fleet-edr-"$TAG".pkg  # Gatekeeper accepts: source=Notarized Developer ID
```

## Report

Summarize as a PASS/FAIL table: asset completeness, checksums, each blob's Sigstore verification, the image signature (+ `:latest` digest match for stable), provenance attestations, and the Gatekeeper checks. Any failure means the release is not safe to announce: name the specific artifact and the failing check, and do not declare the release verified. Clean up the temp dir when done.
