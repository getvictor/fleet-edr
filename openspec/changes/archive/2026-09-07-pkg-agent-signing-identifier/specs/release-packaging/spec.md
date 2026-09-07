# Release packaging: packaged agent code-signing identifier delta

## ADDED Requirements

### Requirement: The packaged agent carries the identifier the extension expects

The system extension authenticates its XPC peer partly by code-signing identifier, so the agent shipped in the package MUST carry the identifier the extension is built to accept. The identifier SHALL be set explicitly at signing time rather than inherited from the signing tool's default, because that default varies with the signing mode: an ad-hoc signature of a bare executable derives a name that includes a content hash, which the extension does not accept.

This applies to the dry-run path as well as the release path. A package whose agent cannot establish its extension session installs successfully and then produces no telemetry, with the failure visible only as a health condition, so the dry-run path being usable is part of what makes it a meaningful rehearsal.

#### Scenario: The packaged agent is accepted by the extension

- **GIVEN** a package built by the dry-run path, without release signing material
- **WHEN** it is installed on a host whose extension is built for development
- **THEN** the agent establishes its session with the extension
- **AND** the extension component does not report never-connected

#### Scenario: The identifier does not vary with signing mode

- **WHEN** the agent is signed by either the dry-run or the release path
- **THEN** the resulting binary carries the same code-signing identifier
