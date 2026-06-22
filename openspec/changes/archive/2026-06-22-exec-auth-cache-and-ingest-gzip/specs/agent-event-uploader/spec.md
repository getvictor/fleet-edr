# Agent Event Uploader Specification

## MODIFIED Requirements

### Requirement: Bounded request size

The system MUST cap the size of each upload request and split larger queue contents across multiple requests so that any single HTTP request stays within the server's accepted body size and the network's practical MTU for streaming bodies. The system SHALL gzip-compress the request body and set `Content-Encoding: gzip`, because event batches are small, repetitive JSON that compress several-fold and the ingest path is bandwidth-bound; the uncompressed batch still drives the over-cap split-and-retry recovery, which bisects by event count and is unaffected by the wire encoding.

#### Scenario: Queue holds more events than fit in one request

- **GIVEN** the queue contains more events than the per-request batch limit
- **WHEN** the uploader runs an upload cycle
- **THEN** the uploader emits one or more requests of bounded size
- **AND** events that did not fit in the first request remain queued for subsequent requests

#### Scenario: The upload body is gzip-compressed

- **GIVEN** the uploader has a batch to send
- **WHEN** it posts the batch to the server
- **THEN** the request carries `Content-Encoding: gzip` and the body is a gzip stream that decompresses to exactly the JSON array of events the uploader marshalled
