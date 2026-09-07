# Server identity authorization: latency gate reading delta

## MODIFIED Requirements

### Requirement: Authorization decisions sub-millisecond at p99

The system SHALL evaluate the authorization chokepoint at p99 latency under 1 millisecond on the deployment's production hardware. The benchmark harness MUST run on every authorization-touching pull request, and a regression that pushes p99 above 1 ms SHALL fail the build. The benchmark MUST cover allow and deny paths and MUST use the seeded roles plus a representative role-binding fan-out.

The benchmark SHALL read p99 in a way that is robust to contention on the machine it runs on, because it runs on shared continuous-integration hardware rather than the production hardware the budget is scoped to. A single reading of the tail on a busy machine measures that machine's contention as much as the code, and reporting it as a regression is indistinguishable from a real one.

#### Scenario: Benchmark passes on the merge candidate

- **GIVEN** a pull request that touches the authorization engine, the policy bundle, or the action registry
- **WHEN** continuous integration runs the authorization benchmark
- **THEN** the recorded p99 over the standard input set is below 1 millisecond
- **AND** the build passes

#### Scenario: Benchmark regression blocks the build

- **GIVEN** a change that pushes authorization p99 latency above 1 millisecond
- **WHEN** continuous integration runs the authorization benchmark
- **THEN** the build fails

#### Scenario: A busy machine does not report a regression

- **GIVEN** a machine under load from unrelated work while the benchmark runs
- **WHEN** the authorization code itself is within the budget
- **THEN** the benchmark does not report a regression
