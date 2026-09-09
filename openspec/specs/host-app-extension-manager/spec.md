# Host App Extension Manager Specification

## Purpose

The host app is the small command-line entry point that installers, MDM scripts, and operators use to bring the EDR's on-device components into and out of an active state. It owns no telemetry, no policy, and no network: it exists purely to drive Apple's system-extension activation flow, the Network Extension content-filter configuration, and the DNS proxy configuration. Without it, the system extension and network extension are inert binaries on disk; with it, they are registered with the operating system, surfaced in System Settings for user approval, and bound to the configurations that make them actually capture events.

The behavior described here is the contract operators rely on. It defines which subcommands exist, what each one does to the OS-managed extension and filter state, how concurrent activations of the two extensions are handled, and how the configurations persist across reboots so the EDR comes back online without operator intervention.

## Requirements

### Requirement: Activate subcommand registers both extensions and enables the filter

The host app SHALL provide an `activate` subcommand that submits an activation request for both the system extension (Endpoint Security) and the network extension, and on success enables both the network content filter AND the DNS proxy. Enabling the DNS proxy as part of `activate` makes the third telemetry stream (DNS) on by default, so a freshly activated host emits correlated exec, network, and DNS events without a separate opt-in step. The DNS proxy remains independently toggleable afterward via `disable-dns-proxy` / `enable-dns-proxy`. The user MAY be required to approve the extensions in System Settings; the subcommand MUST report when approval is pending.

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

### Requirement: Deactivate subcommand removes both extensions

The host app SHALL provide a `deactivate` subcommand that submits a deactivation request for both extensions. After successful deactivation, the extensions MUST no longer run on the device.

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

The host app SHALL provide `enable-filter` and `disable-filter` subcommands that toggle the system-wide content filter on or off. Toggling the filter MUST NOT activate or deactivate either extension.

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

The host app SHALL provide `enable-dns-proxy` and `disable-dns-proxy` subcommands that toggle the DNS proxy provider on or off. The DNS proxy is independent of the content filter; toggling one MUST NOT toggle the other.

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

Once the host app has enabled the content filter or the DNS proxy, the configuration SHALL persist across reboots so the extensions resume capture without operator action after the host comes back up.

#### Scenario: Reboot recovers active configuration

- **GIVEN** an operator activated both extensions and enabled the content filter and the DNS proxy
- **WHEN** the host reboots
- **THEN** after reboot both extensions are loaded by the operating system
- **AND** the content filter is still enabled
- **AND** the DNS proxy is still enabled
- **AND** event capture resumes without operator action

### Requirement: Subcommand parsing fails loudly on unknown input

The host app SHALL refuse to interpret a malformed invocation as a valid action. A malformed invocation is any of: a subcommand that is not in the documented set (typo, deprecated name), an empty subcommand argument (`edr ""`, typically the result of a shell-expansion bug), or one or more extra positional arguments after a valid subcommand (`edr deactivate typo`). On any of these the host app MUST print a usage message that lists the documented subcommands and MUST exit with a non-zero status. The host app MUST NOT silently default malformed input to an activation request and MUST NOT silently drop extra positional arguments.

#### Scenario: Unknown subcommand exits with usage and non-zero status

- **GIVEN** the host app binary
- **WHEN** an operator runs `edr` with any of these malformed forms: a subcommand the binary does not recognise (for example a typo `deactvate`), an empty subcommand argument (`edr ""`), or extra positional arguments after a valid subcommand (`edr deactivate typo`)
- **THEN** the host app prints a usage message listing the documented subcommands
- **AND** the host app exits with a non-zero status
- **AND** the host app does NOT submit an activation request

### Requirement: Activation reports completion outcomes

The host app SHALL report whether each activation completed immediately, completed but requires a reboot to take effect, or failed. The exit status MUST reflect failure if any submitted request reports an error.

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

### Requirement: A staged upgrade surfaces a reboot-required signal

When an activation request reports that it will complete after reboot (the operating system is deferring removal of a previous extension version), the host app SHALL surface a distinct operator-facing signal that a reboot is required to finish the upgrade and restore network and DNS coverage. A fresh activation that completes without a deferred reboot SHALL NOT surface this signal.

#### Scenario: Activation will complete after reboot

- **GIVEN** an activate invocation
- **WHEN** at least one extension request reports it will complete after reboot
- **THEN** the host app surfaces the reboot-required signal
- **AND** the host app still exits successfully so the activation is not retried prematurely

#### Scenario: Fresh activation does not prompt for reboot

- **GIVEN** an activate invocation
- **WHEN** every extension request completes without a deferred reboot
- **THEN** the host app does not surface the reboot-required signal

### Requirement: Activation outcomes are reported to the operator

The host app's activation command is run both by a human and by the install path's activation service, and its exit code is frequently the only signal either one has. It SHALL therefore report what happened, not merely exit with a status.

Every terminal outcome of an extension request SHALL be reported on the command's output: that it was submitted, that it completed, that it will complete after a reboot, that it is awaiting approval, and that it failed. A failure SHALL carry the reason it failed.

Failures SHALL be reported on the error stream rather than the standard output stream, so a caller that captures or redirects normal output still observes them.

Where an outcome is also written to the system log, the message SHALL be readable there. Values that are not sensitive SHALL NOT be recorded in a form that redacts them, because a reason nobody can read is not a diagnostic.

#### Scenario: A failed activation states why

- **GIVEN** an extension activation request that the system rejects
- **WHEN** the operator runs the activation command
- **THEN** the command exits non-zero
- **AND** the reason for the failure is written to the error stream
- **AND** the same reason is readable in the system log

#### Scenario: Awaiting approval is reported rather than silent

- **GIVEN** a host where the extension requires user approval
- **WHEN** the activation command submits its request
- **THEN** the command reports that it is waiting for approval
- **AND** it remains running while the request is pending

#### Scenario: A successful activation still reports its result

- **GIVEN** a host where the extension activates
- **WHEN** the operator runs the activation command
- **THEN** the command reports the outcome and exits zero

### Requirement: Preference toggles are bounded and fail with guidance

The `enable-filter`, `disable-filter`, `enable-dns-proxy` and `disable-dns-proxy` subcommands SHALL bound the NetworkExtension preferences round-trip they perform, and SHALL report a failure naming the subcommand, the bound it exceeded, and what the operator can do about it when the round-trip does not complete within that bound. They SHALL NOT wait without limit.

The bound SHALL be long enough for a person to answer a system consent prompt. Saving a configuration the machine has not yet approved raises that prompt and does not return until it is answered, so a bound chosen to fail quickly would abort a supported interactive flow rather than protect it. The bound exists to put a ceiling on an otherwise unbounded wait, not to make the command fail sooner.

Exactly one outcome SHALL be reported. A round-trip that completes as the bound elapses SHALL NOT report both a result and a timeout.

The `activate` subcommand is deliberately NOT bounded: its flow includes waiting for a human to approve a system-extension installation, so waiting is correct there rather than a defect. Because `activate` chains two provider enables in one process, the single-outcome rule above SHALL apply per bounded invocation and SHALL NOT silence the second link of an unbounded chain.

#### Scenario: A stalled round-trip fails within the bound

- **GIVEN** a preference-toggle subcommand whose preferences round-trip never calls its completion handler
- **WHEN** the bound elapses
- **THEN** the subcommand reports a failure naming the subcommand and the bound
- **AND** the failure distinguishes an unanswered consent prompt from an unresponsive preferences daemon, and gives the console-user remedy for the first
- **AND** the subcommand exits non-zero rather than continuing to wait

#### Scenario: A completed round-trip is unaffected

- **GIVEN** a preference-toggle subcommand whose preferences round-trip completes normally
- **WHEN** it reports its result
- **THEN** the result is the one the round-trip produced, and no timeout is reported

#### Scenario: A result at the deadline reports once

- **GIVEN** a preference-toggle subcommand whose round-trip completes at the moment the bound elapses
- **WHEN** both the completion handler and the bound's watchdog attempt to report
- **THEN** exactly one of them reports, and the other is discarded
