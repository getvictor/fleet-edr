## ADDED Requirements

### Requirement: Deployments allow the server to finish shutting down

Every deployment artefact this project ships that runs the server SHALL allow it at least the sum of every bounded stage of a graceful stop before killing it: the drain window, the deadline for in-flight requests, each wait for background loops to return, and the final telemetry flush. A graceful shutdown that is cut short is not a slower shutdown, it is no shutdown: the readiness probe never completes the window the load balancer is watching, in-flight requests are severed rather than drained, long-lived streams are killed rather than ended, and the telemetry describing all of that is never flushed.

The allowance SHALL exceed that sum rather than equal it, so that the window is not also the deadline that ends it. Counting only the first stages is the error this is written against: they look like the whole shutdown and are not, so a deployment sized against them is killed during a later stage instead of an earlier one.

The relationship SHALL be enforced mechanically rather than by review. These are two numbers in two different file formats, one of which is not read by anything that compiles, and raising the drain without raising the allowance is a change that presents as nothing at all until a replica is next rolled.

Operator documentation SHALL state the requirement for deployments this project does not ship, naming the setting that grants it in the environments the documentation covers. An operator running the server under an orchestrator it does not ship a file for has the same obligation and no artefact of ours to inherit it from.

#### Scenario: A shipped deployment outlasts the shutdown it triggers

- **GIVEN** any deployment artefact in this project that runs the server
- **WHEN** it stops the server
- **THEN** it allows more than every bounded stage of the shutdown put together before killing the process
- **AND** the server completes its drain, its in-flight requests, and its final telemetry flush

#### Scenario: Raising the drain without raising the allowance is caught

- **GIVEN** a change that lengthens any stage of the shutdown
- **WHEN** the project's tests run
- **THEN** any shipped deployment that no longer allows enough time fails the build
- **AND** the failure names the deployment and every duration it was measured against
