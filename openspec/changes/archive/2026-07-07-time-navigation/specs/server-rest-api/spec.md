## ADDED Requirements

### Requirement: Host activity histogram endpoint

The system SHALL expose `GET /api/hosts/{host_id}/activity-histogram` accepting a `from`/`to` nanosecond window and returning the count of process starts per time bucket within it, together with the bucket size. The server SHALL derive the bucket size from the window so the number of buckets stays bounded regardless of the window's width. The bucket counts MUST sum to the total number of process starts in the window, and the endpoint SHALL be authorized by the same host-read action as the process tree.

#### Scenario: Bucketed counts cover the window

- **GIVEN** a host with process starts spread across a requested window
- **WHEN** the client calls the activity-histogram endpoint
- **THEN** the response carries per-bucket counts whose sum equals the number of process starts in the window
- **AND** each start is counted in the bucket containing its start time

#### Scenario: Bucket size scales with the window

- **GIVEN** two requests whose windows differ by an order of magnitude
- **WHEN** each response is returned
- **THEN** each derives a bucket size that keeps the bucket count bounded rather than returning one bucket per fixed interval

#### Scenario: Invalid window is rejected

- **GIVEN** a request whose `from` is not before its `to`
- **WHEN** the client calls the endpoint
- **THEN** the response status is 400
