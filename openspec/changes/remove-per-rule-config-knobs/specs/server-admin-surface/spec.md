# server-admin-surface (delta: retire per-rule config knobs)

## MODIFIED Requirements

### Requirement: Per-rule documentation endpoint

The system SHALL expose `GET /api/rules` returning the per-rule documentation surface the admin UI's rule-detail page relies on. The response MUST include, for every registered rule, the rule's `id`, the list of ATT&CK `techniques` it covers, and a `doc` object carrying at least `title`, `summary`, `description`, `severity`, and `event_types`. When a rule declares false-positive sources or limitations, those MUST be exposed under `false_positives` and `limitations` respectively.

The "Rule with config knobs" scenario is dropped: per-rule config knobs (`doc.config`) are retired (rule tuning moved to the DB-backed detection-config surface in #459), so the endpoint no longer exposes a `config` array.

#### Scenario: Operator reads the rule catalog

- **GIVEN** a server with one or more rules registered
- **WHEN** the operator requests `GET /api/rules`
- **THEN** the server returns `200 OK` with a `rules` array
- **AND** each entry carries `id`, `techniques`, and a non-empty `doc` block with `title`, `summary`, `description`, `severity`, and `event_types`
