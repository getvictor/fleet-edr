# Server process graph builder: the image running at an instant delta

## ADDED Requirements

### Requirement: A process lookup at an instant returns the image that was running then

The system SHALL resolve a process lookup at an instant to the generation whose IMAGE was running at that instant, and SHALL NOT resolve it by when the process was forked.

The two differ whenever a process replaces its image. Executing preserves the fork time, so every generation of one pid carries the same one, and ordering by it cannot distinguish them: the answer becomes whichever generation happened to be recorded last. For a process that forked a child and then executed something else, that is an image which had not run when the child was forked.

A generation that has forked and not yet executed SHALL still be resolvable, at its fork instant, because that is the only start instant such a generation has.

This matters because it is the lookup that answers every parent-image and attribution question. A wrong answer costs the detection and not only its label: a parent that executed something benign after the fork reads as benign, so the rule that would have fired does not.

#### Scenario: A parent that re-executed after the fork still reports the forking image

- **GIVEN** a process that forked a child and then replaced its image with a different binary
- **WHEN** the process is looked up at the instant it forked the child
- **THEN** the image it was running at that instant is returned, not the one it adopted afterwards

#### Scenario: The adopted image is returned once it is running

- **GIVEN** the same process after it has replaced its image
- **WHEN** it is looked up at or after that instant
- **THEN** the adopted image is returned

#### Scenario: A generation that has not executed is still resolvable

- **GIVEN** a generation that forked and has not executed
- **WHEN** it is looked up at its fork instant
- **THEN** it is returned
