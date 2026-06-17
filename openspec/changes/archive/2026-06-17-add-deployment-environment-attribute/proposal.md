# Emit a deployment environment resource attribute

## Why

When several fleet-edr deployments (dev, staging, a pilot tenant) export OTLP to the same SigNoz backend, their telemetry is indistinguishable: every span, metric, and log lands in one undifferentiated stream because the resource carries no environment marker. SigNoz dashboards cannot scope to one environment, and an operator reading a panel cannot tell which deployment a spike came from. The OTel semantic convention for this is the `deployment.environment.name` resource attribute (with the older `deployment.environment` still consumed by some backends, SigNoz included). The binaries do not set it today, so the key is simply absent. This mirrors fleetdm/fleet#47574, which did the same for the Fleet server and its SigNoz dashboards.

## What changes

- **The telemetry resource always carries a deployment environment.** `buildResource` sets both `deployment.environment.name` and the deprecated `deployment.environment` to `default`. Emitting them unconditionally guarantees the key exists in every backend a binary reports to, which is what lets a dashboard offer a dynamic environment selector that populates on any instance.
- **The default is overridable via `OTEL_RESOURCE_ATTRIBUTES`.** The defaults are added before the env detector in `resource.New`, so an operator running multiple environments scopes each by setting `OTEL_RESOURCE_ATTRIBUTES=deployment.environment=<name>` (and/or `deployment.environment.name=<name>`); the env value wins on conflict.
- **The bundled dashboards template + filter on it.** Both `config/observability/` SigNoz dashboards gain an `environment` dynamic variable bound to the `deployment.environment` resource attribute (defaulting to ALL), and every widget query ANDs `deployment.environment IN $environment` into its filter so panels scope to the selected environment(s).

### Not in this change

- A multi-environment config surface in the product. fleet-edr ships a single environment today; the attribute is fixed to `default` and only an operator-supplied `OTEL_RESOURCE_ATTRIBUTES` changes it.
- Per-environment alerting or dashboard provisioning automation.
