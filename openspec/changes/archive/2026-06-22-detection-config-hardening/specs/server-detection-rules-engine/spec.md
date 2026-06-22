# Server detection rules engine specification

## ADDED Requirements

### Requirement: Path exclusions match across the macOS /private firmlink boundary

A detection exclusion of match type `path_glob` or `parent_path_glob` SHALL suppress a matching finding regardless of whether the candidate path is expressed in the public form (`/etc`, `/var`, `/tmp`) or the `/private`-prefixed firmlink form, because macOS resolves the two as the same file and ESF may report either. The operator-entered glob is matched against both macOS forms of the concrete candidate path; the glob itself MUST NOT be rewritten (a glob such as `*/claude/versions/*` cannot be canonicalized), and a candidate path under none of the aliasable prefixes is matched once with no extra cost.

#### Scenario: An exclusion matches the aliased form of the candidate path

- **GIVEN** a `path_glob` exclusion an operator wrote as `/etc/sudoers`
- **WHEN** a rule evaluates a candidate path that ESF reported as `/private/etc/sudoers`
- **THEN** the exclusion suppresses the finding
- **AND** the reverse holds: an exclusion written as `/private/etc/*` suppresses a candidate reported as `/etc/sudoers`

### Requirement: Detection configuration converges across replicas

Each server replica SHALL converge its in-memory detection-config snapshot with mutations made on other replicas without a restart. A mutation bumps a shared monotonic version counter; every replica periodically polls that counter and reloads its snapshot when the stored version has advanced past the loaded snapshot's, so an exclusion or rule-mode change made through one replica takes effect on every replica within the refresh interval. The poll reads only the single-row version counter, so a steady state with no configuration churn costs one indexed read per interval per replica.

#### Scenario: A replica adopts a configuration change made on another replica

- **GIVEN** two replicas sharing one database, each holding a loaded detection-config snapshot that excludes nothing
- **WHEN** an operator creates an exclusion through one replica
- **THEN** the other replica reloads its snapshot on a subsequent refresh tick
- **AND** begins suppressing the matching finding without a restart and without a mutation of its own
