## ADDED Requirements

### Requirement: Process node conviction evidence

Hovering a process node in the tree SHALL show the process's full command line and its derived code-signing verdict without opening the detail panel. Command lines SHALL be rendered faithfully: an argument containing whitespace or a quote is quoted so argv boundaries stay visible. The verdict SHALL be derived from the code-signing fields the node carries and SHALL distinguish: unsigned (no code-signing block reported, or a block with no identity), invalid (a reported signature the kernel no longer considers valid), ad-hoc (the ad-hoc signing flag set), Developer ID with the team identifier (a non-empty team id), Apple platform (the platform-binary flag), and signed (a signing identity with none of the above). A fork-only node (a process that has not exec'd) SHALL show its command line without a verdict: it runs its parent's inherited image, and labeling it unsigned would be a false conviction. Nodes whose verdict is unsigned, invalid, or ad-hoc SHALL carry a visible marker in the graph, distinct from the alert styling and preserved while the node is search-highlighted. For an aggregated node, the hover SHALL state the group size and show the representative process's command line and verdict.

#### Scenario: Hovering a node shows the command line and verdict

- **GIVEN** a rendered process tree containing a Developer ID-signed process
- **WHEN** the operator hovers its node
- **THEN** a tooltip shows the process's full command line
- **AND** the verdict names Developer ID with the team identifier
- **AND** the detail panel does not open

#### Scenario: Unsigned and ad-hoc nodes are marked in the graph

- **GIVEN** a tree containing an unsigned process and an ad-hoc-signed process
- **WHEN** the tree renders
- **THEN** both nodes carry the evidence marker
- **AND** a platform-signed process's node does not

#### Scenario: Aggregated node hover describes the group

- **GIVEN** a tree containing an aggregated node collapsing several identical-path siblings
- **WHEN** the operator hovers it
- **THEN** the tooltip states the member count and shows the representative's command line and verdict

## MODIFIED Requirements

### Requirement: Process detail content

The process detail panel SHALL render, for the selected process: the path, the argument vector, the UID, the GID, the SHA-256 hash, the code-signing verdict together with the signing identity and team identifier (the verdict only for a process that has exec'd, mirroring the tree's fork-only rule), the network connections attributed to the process, the DNS queries attributed to the process, and the re-exec chain (the prior process generations that led to the current image). The command line, path, SHA-256 hash, cdhash (when present), signing identity, and team identifier MUST each be copyable in one click. The panel MUST expose a "Kill process" control that issues a kill command targeting the selected PID.

#### Scenario: Process detail surfaces investigation fields

- **GIVEN** the operator selects a process
- **WHEN** the detail panel renders
- **THEN** the panel shows the path, args, UID, GID, SHA-256, the code-signing verdict with signing identity and team identifier, attributed network connections, attributed DNS queries, and the re-exec chain (when present)

#### Scenario: Evidence fields copy in one click

- **GIVEN** the detail panel is displayed for a signed process
- **WHEN** the operator activates a copy control
- **THEN** the corresponding value (command line, path, SHA-256, cdhash, signing identity, or team identifier) is copied to the clipboard

#### Scenario: Verdict distinguishes the signer categories

- **GIVEN** processes signed as Apple platform, Developer ID, ad-hoc, and one reporting no code-signing block
- **WHEN** each process's detail panel renders
- **THEN** the verdicts read Apple platform, Developer ID with the team identifier, ad-hoc, and unsigned respectively

#### Scenario: Operator kills a running process

- **GIVEN** the process detail panel is displayed for a process that has not exited
- **WHEN** the operator activates the kill control
- **THEN** the UI issues a kill command for that PID and reflects the command's lifecycle state (pending, completed, or failed)
