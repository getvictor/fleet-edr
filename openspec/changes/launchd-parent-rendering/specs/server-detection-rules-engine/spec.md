# Server detection rules engine: launchd parent rendering delta

## ADDED Requirements

### Requirement: A launchd-parented chain names pid 1 and can be suppressed

A shell-chain finding whose shell was started directly by pid 1 SHALL name `/sbin/launchd` as the chain's parent, and SHALL be suppressed by a parent-path-glob exclusion matching it.

Pid 1 is what such a shell's parent IS on macOS, so naming it is a statement of fact rather than a synthetic stand-in for a missing process row. That is what makes the exclusion meaningful: an operator writing a glob for it is excluding the thing the alert names.

The system SHALL NOT report a claimed parent process id of 0 as pid 1. Process 0 is the kernel, so naming it launchd would state something false, and would let an exclusion written for launchd silence a chain that was never launchd's.

A finding with no resolved parent process row SHALL remain unsuppressable by a SIGNATURE exclusion, whether or not its parent is nameable. With no row there is no signing identity to read, and reporting one would contradict the requirement that an unsigned binary at a benign-looking path is never silently allowed.

Suppressing this class is BROAD by nature, and the system SHALL state that where an operator would act on it. An exclusion matching pid 1 silences every launchd-started shell chain for that rule, which includes real persistence execution; the breadth is a property of suppressing the class rather than of how the parent is named, so it is documented rather than designed away.

#### Scenario: A launchd-parented chain names pid 1

- **GIVEN** a shell started directly by pid 1 whose chain would otherwise raise a finding
- **WHEN** the rule evaluates it
- **THEN** the finding names `/sbin/launchd` as the chain's parent rather than reporting the parent as unnameable

#### Scenario: A launchd-parented chain can be suppressed by a parent path exclusion

- **GIVEN** a shell started directly by pid 1 whose chain would otherwise raise a finding
- **AND** a parent-path-glob exclusion matching pid 1's path for that rule
- **WHEN** the rule evaluates it
- **THEN** no finding is produced

#### Scenario: An exclusion for another path leaves a launchd-parented chain firing

- **GIVEN** a shell started directly by pid 1 whose chain would otherwise raise a finding
- **AND** a parent-path-glob exclusion for some other path for that rule
- **WHEN** the rule evaluates it
- **THEN** the finding is still produced, because suppression is no broader than what the operator wrote

#### Scenario: A claimed parent of process 0 is not named as pid 1

- **GIVEN** a shell claiming a parent process id of 0
- **WHEN** the rule evaluates it
- **THEN** the parent is reported as unnameable rather than as pid 1
- **AND** an exclusion matching pid 1's path does not suppress it

## MODIFIED Requirements

### Requirement: Version-agnostic parent allowlist matching

A rule's non-shell parent exclusions SHALL match an entry against the candidate parent process path treating the `*` character as a wildcard that matches any run of characters including the path separator. An entry that contains no `*` MUST match only by exact string equality, preserving the behavior of existing literal-path configurations. A candidate whose non-shell parent matches an entry is suppressed for the rule that entry names. A finding whose parent cannot be named is never suppressed by an entry, and NO finding lacking a resolved parent process record is ever suppressed by a code-signing exclusion, because there is no signing identity to match against. A shell started directly by process 1 is the exception to the first of those: process 1 is nameable, so an entry naming its path does match, which is what makes that class suppressible at all. Entries are per rule: the temp-exec and outbound-connect shapes are separate rules, so an entry saved against one does not suppress the other. The entries are the durable per-rule exclusions on the detection-configuration surface; the `EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST` environment variable this requirement previously named no longer exists.

#### Scenario: A glob allowlist entry suppresses a version-stamped parent

- **GIVEN** a `shell_network_connect` exclusion set containing the entry `*/claude/versions/*`
- **AND** a chain whose non-shell parent path is `/Users/dev/.local/share/claude/versions/2.1.178/claude` spawns a shell that makes an outbound connection to a public address
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the engine produces no `shell_network_connect` finding, because the version-stamped parent path matches the glob entry

#### Scenario: A literal allowlist entry still matches exactly

- **GIVEN** a `shell_network_connect` exclusion set containing the literal entry `/usr/libexec/sshd-session`
- **AND** an otherwise-identical chain whose non-shell parent path is `/usr/libexec/sshd-session`
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the engine produces no `shell_network_connect` finding, because the literal entry matches the parent path exactly
