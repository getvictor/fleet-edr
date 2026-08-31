# Detection rules engine

## ADDED Requirements

### Requirement: A rule declares the mode it operates in absent configuration

A detection MAY declare the mode it operates in when no configuration applies to it. A detection that declares none SHALL operate in `alert`.

A declared default SHALL apply whenever no setting matches the (rule, host) being evaluated, including when no detection-configuration surface is available at all. A configured setting SHALL override a declared default, so that an operator's instruction is never overridden by the rule's own declaration.

When a configured mode cannot be interpreted, the system SHALL apply the declared default rather than alerting. An uninterpretable stored value is not an instruction to alert; alerting would promote a rule whose author declared otherwise on the strength of a value the system could not read. A severity override accompanying an uninterpretable mode SHALL still be honoured, being legible when the mode is not.

A declared default SHALL be reported by the operator-facing rule catalog, and SHALL be distinguishable there from a mode resolved from configuration. The rule-settings surface lists only settings an operator created, so a rule left at its own default appears on no other surface and would otherwise be indistinguishable from one that alerts.

#### Scenario: A rule declaring no default alerts

- **GIVEN** a registered detection that declares no default mode
- **WHEN** a finding it produces is routed and no setting applies to it
- **THEN** the finding is persisted as an alert

#### Scenario: A rule declaring a default operates in it when nothing is configured

- **GIVEN** a registered detection that declares `monitor` as its default mode
- **WHEN** a finding it produces is routed and no setting applies to it
- **THEN** no alert is persisted and the would-be detection is recorded as an observability signal

#### Scenario: A configured setting overrides a declared default

- **GIVEN** a registered detection that declares `monitor` as its default mode, and an operator setting for it whose mode is `alert`
- **WHEN** a finding it produces is routed
- **THEN** the finding is persisted as an alert

#### Scenario: An uninterpretable configured mode falls back to the declared default

- **GIVEN** a stored setting whose mode is a value this build does not recognise, for a detection that declares `monitor`
- **WHEN** the mode for that detection is resolved
- **THEN** the resolved mode is `monitor` rather than `alert`
- **AND** a severity override carried by that setting is still returned

#### Scenario: A declared default is listed on the rule catalog

- **GIVEN** a registered detection that declares a default mode
- **WHEN** an operator reads the rule catalog surface
- **THEN** the entry for that detection reports the mode it operates in absent configuration
