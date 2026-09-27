## ADDED Requirements

### Requirement: Beacon exclusions by domain or program

The `dns_c2_beacon` rule SHALL consult exclusions of match types `domain`, `path_glob`, `team_id`, `signing_id` and `cdhash`, and SHALL declare exactly that set as the match types it supports. A `domain` exclusion MUST be matched against the domain whose lookup the connection is attributed to, as that name or any subdomain of it. The other four MUST be matched against the connecting process: `path_glob` against its executable path, `team_id` and `cdhash` against its recorded code signature, and `signing_id` against its signing identifier qualified by the team that signed it (or by `platform` for an operating-system binary), so a binary without that team's signature cannot match a vendor's `signing_id` exclusion. A matching exclusion SHALL suppress the finding for that connection and nothing else: it MUST NOT suppress a finding for a connection whose attributed domain and process it does not match.

#### Scenario: A domain exclusion waives that domain and its subdomains

- **GIVEN** a `domain` exclusion for `example.com` on `dns_c2_beacon`
- **AND** a process exec'd from a temporary path that looked up `api.example.com` and connected to an address that lookup returned
- **WHEN** the `network_connect` event is evaluated
- **THEN** the engine produces no `dns_c2_beacon` finding

#### Scenario: A domain exclusion does not waive a different domain

- **GIVEN** a `domain` exclusion for `example.com` on `dns_c2_beacon`
- **AND** a process exec'd from a temporary path that looked up `notexample.com` and connected to an address that lookup returned
- **WHEN** the `network_connect` event is evaluated
- **THEN** the engine produces one `dns_c2_beacon` finding

#### Scenario: A program is waived by path or code signature

- **GIVEN** a `path_glob`, `team_id`, `signing_id` or `cdhash` exclusion on `dns_c2_beacon` naming the connecting process
- **WHEN** that process's resolve-then-connect is evaluated
- **THEN** the engine produces no `dns_c2_beacon` finding

#### Scenario: An ad-hoc binary cannot claim a vendor signing id

- **GIVEN** a `signing_id` exclusion `Q6L2SF6YDW:com.example.tool` on `dns_c2_beacon`
- **AND** a process exec'd from a temporary path whose signature claims the identifier `com.example.tool` with no team
- **WHEN** its resolve-then-connect is evaluated
- **THEN** the engine produces one `dns_c2_beacon` finding
