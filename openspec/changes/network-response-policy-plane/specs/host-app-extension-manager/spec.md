# host-app-extension-manager

## ADDED Requirements

### Requirement: The DNS proxy toggle subcommands fail fast instead of hanging

The `enable-dns-proxy` and `disable-dns-proxy` subcommands SHALL bound their preferences operation with a timeout and report a clear, actionable failure when it cannot complete, rather than blocking indefinitely. The operation talks to `nesessionmanager` over XPC, which can never return when the subcommand is invoked from a context without a usable session (for example a non-GUI SSH login), and `disable-dns-proxy` is the operator break-glass recovery for a DNS outage: it must not itself hang exactly when it is needed. The runtime health watchdog (see the network-response capability) is the primary automatic recovery; this requirement keeps the manual lever usable as a bounded backstop.

#### Scenario: Disable times out cleanly when the preferences round-trip cannot complete

- **GIVEN** an operator runs `edr disable-dns-proxy` from a context where the preferences round-trip cannot complete
- **WHEN** the timeout elapses without the operation completing
- **THEN** the subcommand exits with a non-zero status and an actionable message rather than blocking indefinitely

#### Scenario: Disable completes normally when the preferences round-trip is available

- **GIVEN** an operator runs `edr disable-dns-proxy` where the preferences round-trip can complete
- **WHEN** the DNS proxy is toggled off
- **THEN** the subcommand reports success and exits
