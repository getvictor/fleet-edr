# Observability instrumentation: deployment environment delta

## ADDED Requirements

### Requirement: Telemetry carries a deployment environment resource attribute

The system SHALL set the `deployment.environment.name` resource attribute on every emitted span, metric, and log, and SHALL also set the deprecated `deployment.environment` attribute to the same value for backends that still key on the older name. Both SHALL default to `default` and SHALL be emitted unconditionally so the attribute key exists in every backend a binary reports to, which lets a dashboard offer a dynamic environment selector that populates on any instance. The default SHALL be overridable via `OTEL_RESOURCE_ATTRIBUTES`: an operator-supplied `deployment.environment` (or `deployment.environment.name`) value MUST win over the built-in `default` so a deployment exporting to a shared backend can scope its telemetry per environment.

#### Scenario: Default deployment environment

- **GIVEN** no `OTEL_RESOURCE_ATTRIBUTES` override for the deployment environment
- **WHEN** the telemetry resource is built
- **THEN** the resource carries `deployment.environment.name` equal to `default`
- **AND** the resource carries the deprecated `deployment.environment` equal to `default`

#### Scenario: Operator overrides the deployment environment

- **GIVEN** `OTEL_RESOURCE_ATTRIBUTES` sets `deployment.environment` (and/or `deployment.environment.name`) to an operator-chosen value
- **WHEN** the telemetry resource is built
- **THEN** the resource carries the operator-supplied value rather than `default`
