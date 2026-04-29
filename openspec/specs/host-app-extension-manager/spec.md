# Host App Extension Manager Specification

## Purpose

The host app is the small command-line entry point that installers, MDM scripts, and operators use to bring the EDR's
on-device components into and out of an active state. It owns no telemetry, no policy, and no network — it exists
purely to drive Apple's system-extension activation flow, the Network Extension content-filter configuration, and the
DNS proxy configuration. Without it, the system extension and network extension are inert binaries on disk; with it,
they are registered with the operating system, surfaced in System Settings for user approval, and bound to the
configurations that make them actually capture events.

The behavior described here is the contract operators rely on. It defines which subcommands exist, what each one does
to the OS-managed extension and filter state, how concurrent activations of the two extensions are handled, and how
the configurations persist across reboots so the EDR comes back online without operator intervention.

## Requirements

### Requirement: Activate subcommand registers both extensions and enables the filter

The host app SHALL provide an `activate` subcommand that submits an activation request for both the system extension
(Endpoint Security) and the network extension, and on success enables the network content filter. The user MAY be
required to approve the extensions in System Settings; the subcommand MUST report when approval is pending.

#### Scenario: First-time activation on an unconfigured machine

- **GIVEN** neither extension is installed and the user has not previously approved EDR system extensions
- **WHEN** an operator runs `edr activate`
- **THEN** the host app submits activation requests for both extensions
- **AND** the host app reports that user approval is pending
- **AND** once the user approves, the host app enables the content filter and exits successfully

#### Scenario: Re-activation when extensions are already approved

- **GIVEN** both extensions were previously activated and are still approved
- **WHEN** an operator runs `edr activate`
- **THEN** the host app replaces the running extensions with the current bundle on disk
- **AND** the host app enables the content filter
- **AND** the host app exits successfully

### Requirement: Deactivate subcommand removes both extensions

The host app SHALL provide a `deactivate` subcommand that submits a deactivation request for both extensions. After
successful deactivation, the extensions MUST no longer run on the device.

#### Scenario: Deactivating an active install

- **GIVEN** both extensions are active
- **WHEN** an operator runs `edr deactivate`
- **THEN** the host app submits deactivation requests for both extensions
- **AND** when both deactivations complete the host app exits successfully
- **AND** the extensions stop running

#### Scenario: One of the two deactivations fails

- **GIVEN** both extensions are active
- **WHEN** an operator runs `edr deactivate` and one of the two deactivation requests reports an error
- **THEN** the host app exits with a non-zero status indicating failure

### Requirement: Filter enable and disable subcommands

The host app SHALL provide `enable-filter` and `disable-filter` subcommands that toggle the system-wide content filter
on or off. Toggling the filter MUST NOT activate or deactivate either extension.

#### Scenario: Disable the filter without removing the extension

- **GIVEN** the network extension is active and the content filter is enabled
- **WHEN** an operator runs `edr disable-filter`
- **THEN** the content filter becomes disabled
- **AND** the network extension remains installed and approved

#### Scenario: Re-enable the filter

- **GIVEN** the network extension is active but the content filter is disabled
- **WHEN** an operator runs `edr enable-filter`
- **THEN** the content filter becomes enabled
- **AND** new outbound flows begin reaching the network extension's filter

### Requirement: DNS proxy enable and disable subcommands

The host app SHALL provide `enable-dns-proxy` and `disable-dns-proxy` subcommands that toggle the DNS proxy provider on
or off. The DNS proxy is independent of the content filter; toggling one MUST NOT toggle the other.

#### Scenario: Enable DNS proxy on top of an active filter

- **GIVEN** the network extension is active with the content filter already enabled
- **WHEN** an operator runs `edr enable-dns-proxy`
- **THEN** the DNS proxy becomes enabled
- **AND** the content filter remains in its prior state

#### Scenario: Disable DNS proxy without affecting other state

- **GIVEN** the DNS proxy is enabled and the content filter is enabled
- **WHEN** an operator runs `edr disable-dns-proxy`
- **THEN** the DNS proxy becomes disabled
- **AND** the content filter remains enabled

### Requirement: Configuration persists across reboots

Once the host app has enabled the content filter or the DNS proxy, the configuration SHALL persist across reboots so the
extensions resume capture without operator action after the host comes back up.

#### Scenario: Reboot recovers active configuration

- **GIVEN** an operator activated both extensions and enabled the content filter and the DNS proxy
- **WHEN** the host reboots
- **THEN** after reboot both extensions are loaded by the operating system
- **AND** the content filter is still enabled
- **AND** the DNS proxy is still enabled
- **AND** event capture resumes without operator action

### Requirement: Activation reports completion outcomes

The host app SHALL report whether each activation completed immediately, completed but requires a reboot to take effect,
or failed. The exit status MUST reflect failure if any submitted request reports an error.

#### Scenario: One extension completes immediately and the other needs a reboot

- **GIVEN** both extensions are submitted via `edr activate`
- **WHEN** one extension reports completion and the other reports it will complete after reboot
- **THEN** the host app reports the reboot-required status
- **AND** the host app exits successfully so the activation is not retried prematurely

#### Scenario: An activation request errors

- **GIVEN** an activation has been submitted
- **WHEN** the operating system reports an error completing the request
- **THEN** the host app reports the error
- **AND** the host app exits with a non-zero status
