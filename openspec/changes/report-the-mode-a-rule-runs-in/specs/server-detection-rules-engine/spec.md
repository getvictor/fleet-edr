# Server detection rules engine

## MODIFIED Requirements

### Requirement: Operator toggling of individual rules

The system SHALL allow an operator to set an individual rule's mode to one of `alert`, `monitor`, or `disabled` through the durable detection-configuration surface (persisted in MySQL, edited via the admin API/UI), NOT through boot-time environment configuration. The mode MAY be set at global scope or scoped to a host group, and resolves per host most-specific-wins (a host-group setting overrides the global setting for hosts in that group). A rule that resolves to `disabled` for a host MUST NOT produce alerts for that host. A rule that resolves to `monitor` for a host MUST evaluate but MUST NOT persist an alert, emitting an observability signal instead so the would-be detection is visible without alerting. A rule that resolves to `alert` produces alerts as normal. A mode change MUST take effect without a server restart.

A rule whose global mode is `disabled` MUST remain visible in the rule catalog surface (`GET /api/rules`) with its mode indicated rather than being removed from the catalog. The mode indicated SHALL be the mode the rule RUNS IN at global scope: the globally scoped setting when one applies, and the rule's own declared default otherwise. The catalog SHALL also report which of those two produced it. A rule's declaration and the mode in force are different facts and a reader needs both: without the source, a rule sitting in `monitor` because that is how it shipped cannot be told from one an operator moved there, and those call for opposite follow-ups.

The mode and its source SHALL be resolved together, from one read of the configuration, so a listing cannot report a mode taken from one configuration version with a source taken from another. A stored setting whose mode the server cannot interpret SHALL report source `default`, because the default is what the server falls back to and therefore where the reported mode came from.

Global scope is what a catalog listing can answer, since the listing names no host. A per-host mode remains a separate resolution the engine performs at evaluation time.

#### Scenario: An operator disables a noisy rule for their environment

- **GIVEN** a running engine and an operator who sets a rule's global mode to `disabled` through the detection-configuration API
- **WHEN** a batch arrives that would otherwise satisfy that rule
- **THEN** no alerts are produced for that rule
- **AND** the remaining rules continue to evaluate normally
- **AND** the disabled rule is still listed by `GET /api/rules`, marked disabled
- **AND** the change took effect without a server restart

#### Scenario: The catalog reports the mode a rule runs in, not only the one it declares

- **GIVEN** a rule that declares `monitor` as its default and an operator setting that sets its global mode to `disabled`
- **WHEN** the rule catalog is listed
- **THEN** the entry reports mode `disabled` and source `setting`
- **AND** it still reports the rule's declared default of `monitor` alongside
- **AND** a rule with no setting reports its declared default with source `default`

#### Scenario: A rule set to monitor evaluates without alerting

- **GIVEN** a rule whose global mode is set to `monitor`
- **WHEN** a batch arrives that satisfies the rule for a host
- **THEN** no alert is persisted for that rule and host
- **AND** an observability signal records that the rule matched

#### Scenario: An operator re-enables a previously disabled rule

- **GIVEN** a rule whose global mode was previously set to `disabled`
- **WHEN** the operator sets its mode back to `alert` through the API
- **THEN** subsequent batches that satisfy the rule produce alerts again without a server restart
