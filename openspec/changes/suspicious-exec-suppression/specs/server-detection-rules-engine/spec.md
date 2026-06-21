# Server Detection Rules Engine Specification

## ADDED Requirements

### Requirement: Version-agnostic parent allowlist matching

The `suspicious_exec` rule's non-shell parent allowlist (configured by `EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST`) SHALL match an allowlist entry against the candidate parent process path treating the `*` character as a wildcard that matches any run of characters including the path separator. An entry that contains no `*` MUST match only by exact string equality, preserving the behavior of existing literal-path configurations. As today, a candidate whose non-shell parent matches an allowlist entry is suppressed for both arms of the rule, and a finding with no resolved non-shell parent is never suppressed by the allowlist.

#### Scenario: A glob allowlist entry suppresses a version-stamped parent

- **GIVEN** a `suspicious_exec` configuration whose parent allowlist contains the entry `*/claude/versions/*`
- **AND** a chain whose non-shell parent path is `/Users/dev/.local/share/claude/versions/2.1.178/claude` spawns a shell that makes an outbound connection to a public address
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the engine produces no `suspicious_exec` finding, because the version-stamped parent path matches the glob entry

#### Scenario: A literal allowlist entry still matches exactly

- **GIVEN** a `suspicious_exec` configuration whose parent allowlist contains the literal entry `/usr/libexec/sshd-session`
- **AND** an otherwise-identical chain whose non-shell parent path is `/usr/libexec/sshd-session`
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the engine produces no `suspicious_exec` finding, because the literal entry matches the parent path exactly

### Requirement: Local-resolver DNS suppression for the network arm

The `suspicious_exec` rule MUST NOT treat an outbound `network_connect` event to remote port 53 as a triggering outbound connection when the event's `remote_address` parses as a local-resolver-class IP address: an IPv4 or IPv6 loopback address, an RFC1918 private address, an IPv4 link-local address, an address in the CGNAT range `100.64.0.0/10`, an IPv6 unique-local address, or an IPv6 link-local address. An outbound connection to port 53 whose `remote_address` is any other (publicly routable) address MUST still be eligible to trigger the network arm. This suppression applies only to the outbound-network arm; it does not affect the temp-path-exec arm.

#### Scenario: Outbound DNS to a local resolver does not count as a network connection

- **GIVEN** a non-shell parent spawns a shell that issues an outbound `network_connect` to `100.100.100.100` on port 53
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the engine produces no `suspicious_exec` finding from the network arm, because the destination is the host's local-resolver-class address on the DNS port

#### Scenario: Outbound DNS to a public resolver still fires

- **GIVEN** a non-shell parent spawns a shell that issues an outbound `network_connect` to `8.8.8.8` on port 53
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the engine produces a `suspicious_exec` finding from the network arm, because the destination is a publicly routable address
