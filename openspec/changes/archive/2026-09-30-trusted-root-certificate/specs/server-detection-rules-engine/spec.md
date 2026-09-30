## ADDED Requirements

### Requirement: A certificate trusted from the command line is reported

The `trusted_root_certificate` rule SHALL fire on an `exec` of `/usr/bin/security` whose subcommand is `add-trusted-cert` or `trust-settings-import`, naming the subcommand and linking the finding to the process. It SHALL NOT fire on another subcommand, including `add-certificates`, on `security help` naming one of those subcommands, on an invocation carrying `-h`, on an `add-trusted-cert` whose result type is `deny` or `unspecified` or that writes its settings to a file with `-o`, or on a binary at another path. The finding for `trust-settings-import` SHALL say it imports trust settings rather than that it trusted a certificate, since the imported file may hold deny entries.

#### Scenario: Security writing trust settings fires

- **GIVEN** an exec of `/usr/bin/security add-trusted-cert -d -r trustRoot ...`, and one of `/usr/bin/security trust-settings-import ...`
- **WHEN** detection evaluates each event
- **THEN** `trusted_root_certificate` raises a high-severity finding naming the subcommand, linked to the process

#### Scenario: Other uses of security do not fire

- **GIVEN** execs of `security add-certificates`, `security help add-trusted-cert`, `security -h add-trusted-cert`, `security add-trusted-cert -h`, `security add-trusted-cert -r deny ...`, `security add-trusted-cert -o <file> ...`, `security find-certificate`, and a `security` binary at `/tmp/security`
- **WHEN** detection evaluates the events
- **THEN** no finding is raised
