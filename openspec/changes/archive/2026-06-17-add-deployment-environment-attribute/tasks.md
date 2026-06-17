# Emit a deployment environment resource attribute: tasks

## 1. Resource

- [x] `internal/observability/observability.go`: in `buildResource`, add `semconv.DeploymentEnvironmentName("default")` + `attribute.String("deployment.environment", "default")` in a `resource.WithAttributes` ordered BEFORE `resource.WithFromEnv()` so `OTEL_RESOURCE_ATTRIBUTES` overrides the defaults on conflict.

## 2. Dashboards

- [x] `config/observability/edr-authz-dashboard.json`: add the `environment` DYNAMIC variable (`dynamicVariablesAttribute: deployment.environment`, source `Traces`, default ALL) and AND `deployment.environment IN $environment` into every widget filter expression.
- [x] `config/observability/edr-http-server-dashboard.json`: same, with variable source `Metrics`.

## 3. Spec

- [x] `observability-instrumentation` spec: ADDED requirement "Telemetry carries a deployment environment resource attribute" with the default + override scenarios.

## 4. Tests

- [x] `internal/observability/observability_test.go`: `TestBuildResource_DeploymentEnvironment` pins the default (both keys = `default`) and the `OTEL_RESOURCE_ATTRIBUTES` override. Scenario markers on both subtests.

## 5. Verification

- [x] `go test ./internal/observability/` green.
- [ ] gofmt, golangci-lint on the touched package; `openspec validate add-deployment-environment-attribute --strict`; spectrace; dash + markdown lints; JSON well-formedness of both dashboards.
