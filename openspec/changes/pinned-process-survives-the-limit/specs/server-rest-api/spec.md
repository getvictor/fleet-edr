## ADDED Requirements

### Requirement: A pinned process is in the page with its ancestors

A process-forest read naming a process to pin SHALL return that process, and every ancestor back to its root, whatever the row limit admitted. A client pins a process because that process is the reason it is reading, so a page that does not contain it has not answered the request, however many other rows it carries.

The row limit alone cannot satisfy this. The read returns the newest rows in the window, so a host busy enough to fill the page after the pinned process forked pushes that process off the page entirely, and does so more reliably the longer an analyst waits before opening the alert.

The ancestors SHALL come with it rather than the pinned row alone. A forest links a child to its parent only among the rows it was given, so a pinned process whose parent is absent is returned as a root: a process presented as having no parent, when it has one the read simply did not fetch.

Each ancestor SHALL be resolved by the same rule the system uses everywhere else to decide which generation of a pid was running at a given instant, because a pid is reused and a second rule for one caller would answer differently from the rest of the system for the same process. The walk SHALL be bounded, so that data claiming a process is its own ancestor cannot make the read run forever.

The counts describing the read SHALL continue to describe the page the limit admitted, not the page plus what the pin added. They exist to tell a client what the read did not return, and a count that silently absorbed the pinned rows would report a page larger than the limit allowed.

A pinned process that no longer exists SHALL NOT fail the read. Retention removes processes while the alerts raised on them remain, and a host's forest is still worth returning to an analyst whose alert has outlived its process.

#### Scenario: The pinned process survives a page of newer activity

- **GIVEN** a host where more processes forked after the pinned process than the row limit admits
- **WHEN** the forest is read for a window containing both, pinning that process
- **THEN** the pinned process is in the result

#### Scenario: Its ancestors come with it

- **GIVEN** the same read
- **WHEN** the result is inspected
- **THEN** every ancestor of the pinned process back to its root is present, so it is returned as part of its chain rather than as a root

#### Scenario: Without a pin the limit still decides the page

- **GIVEN** the same host and window, read without pinning anything
- **WHEN** the result is inspected
- **THEN** it holds only what the row limit admitted

#### Scenario: The counts still describe the page

- **GIVEN** a read whose pin added rows the limit had excluded
- **WHEN** the result metadata is inspected
- **THEN** the count of rows returned is the number the limit admitted
- **AND** the read is still reported as truncated

#### Scenario: A pinned process that no longer exists is not an error

- **GIVEN** a pin naming a process that is not stored
- **WHEN** the forest is read
- **THEN** the read succeeds and returns the host's forest
