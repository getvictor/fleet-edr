## ADDED Requirements

### Requirement: An installer script is waived by its package signer

The `suspicious_exec` rule SHALL consult exclusions of match type `package_team_id` for an installer script: a chain whose non-shell parent is PackageKit's `package_script_service`, whose trigger exec carries the signature of the package the script belongs to. Such an exclusion SHALL suppress the finding only when the package is signed by a certificate macOS trusts and its Developer ID team equals the exclusion's value. It SHALL NOT suppress anything for an unsigned or untrusted package, or for a chain under any other parent, whatever package signature the event carries. The detection configuration SHALL store the match type, and a finding for an installer script SHALL name the package being installed and its signer when known.

#### Scenario: A vendor's installer is waived by its package team

- **GIVEN** a `package_team_id` exclusion for a vendor's team
- **AND** an installer script chain under `package_script_service` whose package that team signed
- **WHEN** the rule evaluates it
- **THEN** no finding is produced
- **AND** an exclusion for another team produces the finding

#### Scenario: Only a trusted package signature counts

- **GIVEN** a `package_team_id` exclusion for a vendor's team
- **AND** an installer script whose package is unsigned, untrusted though naming that team, or carries no reported signature
- **WHEN** the rule evaluates it
- **THEN** a finding is produced

#### Scenario: A signature outside PackageKit counts for nothing

- **GIVEN** a `package_team_id` exclusion for a vendor's team
- **AND** a chain whose parent is not `package_script_service` but whose trigger carries that vendor's package signature
- **WHEN** the rule evaluates it
- **THEN** a finding is produced

#### Scenario: The package team is a storable match type

- **GIVEN** an operator creating a `package_team_id` exclusion
- **WHEN** it is stored and the configuration is loaded
- **THEN** it applies to that match type and not to `team_id`
