## ADDED Requirements

### Requirement: The graph says where retained process records begin

The process-tree endpoint SHALL report the moment before which completed process records have been deleted by retention, so a client can tell a window whose earlier processes aged out from one in which they never existed. It SHALL NOT report one when process retention is disabled, since nothing has been deleted.

#### Scenario: A window past retention is told where records begin

- **GIVEN** a deployment that deletes completed process records after seven days
- **WHEN** a client reads a host's process tree
- **THEN** the response reports a boundary seven days before now

#### Scenario: No boundary when retention is disabled

- **GIVEN** a deployment with process retention disabled
- **WHEN** a client reads a host's process tree
- **THEN** the response reports no boundary
