# Release packaging: artifact signing and extension display names delta

## ADDED Requirements

### Requirement: Release artifacts carry a verifiable Sigstore signature

From the first release that ships the bundle format (v0.2.0) onward, the release pipeline SHALL publish, alongside every signed blob artifact (the package, both `.mobileconfig` profiles, the `SHA256SUMS` manifest, and both SBOMs), a single Sigstore bundle file (`<artifact>.sigstore.json`) that carries the signature, the ephemeral Fulcio signing certificate, and the transparency-log proof in one file. Each bundle MUST verify the artifact against the GitHub Actions workflow identity that produced it, using only non-deprecated cosign flags, so a verifier on a current cosign release sees no deprecation warnings. The pipeline MUST NOT require the legacy `<artifact>.sig` + `<artifact>.pem` pair for releases that ship bundles; releases predating the bundle format keep their existing `.sig`/`.pem` files and the legacy verify command remains valid for them.

#### Scenario: Each released artifact verifies against its published bundle

- **GIVEN** a release tag whose pipeline signs every blob artifact with `cosign sign-blob --bundle`
- **WHEN** a verifier runs `cosign verify-blob --bundle <artifact>.sigstore.json --certificate-identity-regexp <release-workflow-identity> --certificate-oidc-issuer https://token.actions.githubusercontent.com <artifact>` on a current cosign release
- **THEN** verification reports "Verified OK"
- **AND** no deprecated-flag warning is printed

### Requirement: System extensions present recognizable display names

The packaged Endpoint Security and Network system extensions SHALL each carry a `CFBundleDisplayName` that identifies it as a Fleet EDR component, so the macOS System Settings entries (Login Items & Extensions, Full Disk Access) an operator must act on during a manual install are unambiguously attributable to Fleet EDR rather than a generic "extension" / "networkextension" label. The packaging build MUST fail rather than produce a package whose staged extensions carry a non-Fleet-EDR display name.

#### Scenario: Security extension shows a recognizable name

- **GIVEN** a packaging build that stages the Endpoint Security extension into the host app
- **WHEN** the build inspects the staged `com.fleetdm.edr.securityextension.systemextension` bundle
- **THEN** its `CFBundleDisplayName` is "Fleet EDR Security Extension"
- **AND** the build fails if the display name is anything else

#### Scenario: Network extension shows a recognizable name

- **GIVEN** a packaging build that stages the Network Extension into the host app
- **WHEN** the build inspects the staged `com.fleetdm.edr.networkextension.systemextension` bundle
- **THEN** its `CFBundleDisplayName` is "Fleet EDR Network Extension"
- **AND** the build fails if the display name is anything else
