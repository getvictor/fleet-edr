# Ship unsigned mobileconfig profiles

## Why

The release pipeline CMS-signs both `.mobileconfig` profiles with the Developer ID Installer identity. That signature has no consumer and actively breaks the Fleet deployment channel: Fleet rejects pre-signed profiles with "Configuration profiles can't be signed. Fleet will sign the profile for you." The other supported MDM channels (Jamf, Kandji, Intune, mosyle) accept unsigned XML and sign at delivery time. Manual installation is not a consumer either: the `com.apple.system-extension-policy` and `com.apple.TCC.configuration-profile-policy` payloads are MDM-only on modern macOS, so a locally installed profile is ignored regardless of signature, and `docs/install-agent-manual.md` already routes the human through System Settings clicks instead of the profiles. Download authenticity is already covered by the cosign `.sig` + `.pem` pair on every release artifact.

## What changes

- `packaging/profiles/sign.sh` becomes `packaging/profiles/render.sh`: substitute `APPLE_TEAM_ID` into the templates and `plutil -lint`, no CMS signing, no `--dry-run` flag (render is the only mode).
- `release.yml` renders unsigned profiles on both the real-release and dry-run branches; the released artifacts are byte-identical XML either way (modulo team id source).
- `release-secrets-check.yml` no longer signs profiles; it CMS-signs a scratch plist instead, preserving the "Installer private key is usable" guarantee that protects pkg `productsign` at release time.
- Taskfile: `profiles:sign` is removed; `profiles:render` calls `render.sh`.
- Spec delta: the release-packaging requirement now mandates unsigned profiles; the two signed/unsigned scenarios collapse into one `profiles-are-rendered-unsigned` scenario.
- Docs (`docs/README.md`, `docs/mdm-deployment.md`, `docs/fleet-deployment.md`) describe the unsigned contract, plus a Fleet troubleshooting entry for the pre-signed-profile error hit with releases v0.1.1-rc.12 and earlier.

### Not in this change

- Re-signing or re-publishing existing releases: profiles in v0.1.1-rc.12 and earlier stay CMS-signed; the Fleet doc shows how to strip them (`security cms -D`).
