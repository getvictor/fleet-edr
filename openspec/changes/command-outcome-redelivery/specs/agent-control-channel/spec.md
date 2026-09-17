## MODIFIED Requirements

### Requirement: Delivery is at-least-once and idempotent by command identity

The system MAY offer the same command over a connection more than once, and SHALL run a command's side effect at most once. The agent SHALL key execution by command identity and SHALL record each command's final outcome; on re-delivery of a command it has already executed, the agent SHALL re-report the recorded outcome rather than repeating the side effect, so a command whose outcome report was lost still transitions out of pending rather than being silently dropped and left stuck. The server SHALL reject an outcome report that is not a valid transition for the command's current status, which the agent treats as already handled.

A command the agent acknowledged and never reported an outcome for SHALL be offered again to that host while it holds a connection, once a grace period longer than any command's execution has passed since the acknowledgement, and SHALL NOT be offered after a window shorter than the agent's own record of outcomes, beyond which an agent could no longer replay one and would repeat the side effect instead. A command that is still unreported after that window SHALL keep the status it has: it was delivered, and its outcome is not known.

#### Scenario: A re-delivered command re-reports its recorded outcome without repeating the side effect

- **GIVEN** a command that a host already executed but whose outcome report was lost, so the command is still pending on the server
- **WHEN** the command is delivered to that host's connection again
- **THEN** the agent does not repeat the command's side effect
- **AND** the agent re-reports the recorded outcome so the server transitions the command out of pending

#### Scenario: An outcome that is not a valid transition is rejected

- **GIVEN** a command whose status has already advanced past the reported transition
- **WHEN** the agent reports an outcome that the current status does not permit
- **THEN** the server rejects it rather than recording it
- **AND** the agent treats the rejection as already handled, not as a failure

#### Scenario: An acknowledged command is re-offered

- **GIVEN** a host holding a connection, and one of its commands acknowledged longer ago than the grace period with no outcome recorded
- **WHEN** the server next offers that host its commands
- **THEN** the acknowledged command is offered alongside any pending ones
- **AND** a command acknowledged inside the grace period, or longer ago than the redelivery window, is not offered
