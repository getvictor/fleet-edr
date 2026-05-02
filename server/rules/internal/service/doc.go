// Package service is the rules orchestrator: a single struct that
// composes the policy store + the rule catalog + the cross-context
// closures for ActiveHostsLister and CommandInserter into the three
// public interfaces (PolicyService, Catalog, ContentService).
//
// Policy fan-out (the per-host set_blocklist queue write that follows
// every PUT /api/policy and the post-enroll seed) lives here in
// fanout.go. Enroll-time fan-out is consumed by endpoint via
// PolicyService.ActiveCommandPayload; PUT-time fan-out is invoked
// directly by the operator handler.
package service
