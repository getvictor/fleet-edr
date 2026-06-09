# Host-app extension manager — DNS proxy on by default delta

## MODIFIED Requirements

### Requirement: Activate subcommand registers both extensions and enables the filter

The host app SHALL provide an `activate` subcommand that submits an activation request for both the system extension
(Endpoint Security) and the network extension, and on success enables both the network content filter AND the DNS proxy.
Enabling the DNS proxy as part of `activate` makes the third telemetry stream (DNS) on by default, so a freshly activated
host emits correlated exec, network, and DNS events without a separate opt-in step. The DNS proxy remains independently
toggleable afterward via `disable-dns-proxy` / `enable-dns-proxy`. The user MAY be required to approve the extensions in
System Settings; the subcommand MUST report when approval is pending.

#### Scenario: First-time activation on an unconfigured machine

- **GIVEN** neither extension is installed and the user has not previously approved EDR system extensions
- **WHEN** an operator runs `edr activate`
- **THEN** the host app submits activation requests for both extensions
- **AND** the host app reports that user approval is pending
- **AND** once the user approves, the host app enables the content filter and the DNS proxy and exits successfully

#### Scenario: Re-activation when extensions are already approved

- **GIVEN** both extensions were previously activated and are still approved
- **WHEN** an operator runs `edr activate`
- **THEN** the host app replaces the running extensions with the current bundle on disk
- **AND** the host app enables the content filter and the DNS proxy
- **AND** the host app exits successfully
