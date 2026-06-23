# Server admin surface: ATT&CK coverage layer macOS scoping delta

## MODIFIED Requirements

### Requirement: ATT&CK coverage layer endpoint

The system SHALL expose `GET /api/attack-coverage` returning a MITRE ATT&CK Navigator layer JSON document that enumerates the techniques covered by the registered detection rules. The document MUST be importable directly into the upstream MITRE ATT&CK Navigator. Each covered technique MUST identify the rule (or rules) that cover it. The document MUST scope the rendered matrix to the macOS platform via a `filters.platforms` array containing `macOS`, since Fleet EDR is a macOS-only product.

#### Scenario: Coverage when rules are registered

- **GIVEN** at least one detection rule registered with one or more ATT&CK techniques
- **WHEN** the operator requests `GET /api/attack-coverage`
- **THEN** the server returns a Navigator layer JSON whose `techniques` array contains an entry for every covered technique
- **AND** each entry identifies the rule ids that cover that technique

#### Scenario: Coverage with no rules

- **GIVEN** a server with no rules registered
- **WHEN** the operator requests `GET /api/attack-coverage`
- **THEN** the server returns a Navigator layer JSON with an empty `techniques` array rather than an error

#### Scenario: Layer is scoped to the macOS platform

- **GIVEN** a server serving the ATT&CK coverage layer
- **WHEN** the operator requests `GET /api/attack-coverage`
- **THEN** the returned Navigator layer JSON carries `filters.platforms` equal to `["macOS"]`
- **AND** the upstream Navigator renders only the macOS matrix when the layer is imported
