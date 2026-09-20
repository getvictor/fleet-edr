## ADDED Requirements

### Requirement: Deployments allow the server to finish shutting down

Every deployment artefact this project ships that runs the server SHALL allow it at least the drain window plus the shutdown deadline before killing it. A graceful shutdown that is cut short is not a slower shutdown, it is no shutdown: the readiness probe never completes the window the load balancer is watching, in-flight requests are severed rather than drained, long-lived streams are killed rather than ended, and the telemetry describing all of that is never flushed.

The allowance SHALL exceed those two durations rather than equal them, so that the window is not also the deadline that ends it.

The relationship SHALL be enforced mechanically rather than by review. These are two numbers in two different file formats, one of which is not read by anything that compiles, and raising the drain without raising the allowance is a change that presents as nothing at all until a replica is next rolled.

Operator documentation SHALL state the requirement for deployments this project does not ship, naming the setting that grants it in the environments the documentation covers. An operator running the server under an orchestrator it does not ship a file for has the same obligation and no artefact of ours to inherit it from.

#### Scenario: A shipped deployment outlasts the shutdown it triggers

- **GIVEN** any deployment artefact in this project that runs the server
- **WHEN** it stops the server
- **THEN** it allows more than the drain window plus the shutdown deadline before killing the process
- **AND** the server completes its drain, its in-flight requests, and its final telemetry flush

#### Scenario: Raising the drain without raising the allowance is caught

- **GIVEN** a change that lengthens the drain window or the shutdown deadline
- **WHEN** the project's tests run
- **THEN** any shipped deployment that no longer allows enough time fails the build
- **AND** the failure names the deployment and the two durations
