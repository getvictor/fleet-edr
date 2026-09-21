## ADDED Requirements

### Requirement: An alert's chain can be read on its own

The process-forest endpoint SHALL offer a read scoped to one process's chain: that process, its ancestors, and its descendants, and nothing else. A client reading a single alert is asking what that process did and what it came from, and answering with the host's activity over a window costs rows in proportion to how busy the host was rather than to the size of the answer.

A chain read SHALL name the process it is the chain of. Asked for a chain with no process named, the system SHALL read the host's window instead, because a caller that named no process has described the host.

A chain read SHALL NOT count the host's window, and SHALL NOT report the window as truncated. Those describe what a windowed read left out, and a chain read left nothing out because it read no window. Reporting them anyway would tell an analyst that the chain in front of them is part of something larger that was cut short, which is not what happened.

Descendants SHALL be bounded by each process's own lifetime. A process number is reused only once its holder has exited, so a process forked after this one exited belongs to whichever process took the number next; attributing it here would show an analyst activity the process never spawned, under its name.

Descendants SHALL be capped, and a chain read SHALL report truncation only about that cap. They are the one direction with no natural bound: ancestors are bounded by the depth of a process tree, while a single process may spawn without limit.

A chain read naming a process that is not stored SHALL return an empty chain rather than the host's forest. Retention removes processes while the alerts raised on them remain, and answering with the host's activity is the fallback this read exists to remove.

#### Scenario: A chain read returns the chain and nothing else

- **GIVEN** a host carrying unrelated activity alongside a process's chain
- **WHEN** the chain is read for that process
- **THEN** the result holds that process, its ancestors and its descendants
- **AND** none of the host's unrelated activity

#### Scenario: A chain read reports no window truncation

- **GIVEN** a chain read that completed
- **WHEN** its result metadata is inspected
- **THEN** it does not report the read as truncated
- **AND** it does not report a capped count of a window it did not read

#### Scenario: A chain read for a missing process is empty

- **GIVEN** a chain read naming a process that is not stored
- **WHEN** the read completes
- **THEN** the result is empty rather than the host's forest
