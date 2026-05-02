// Package service is the rules orchestrator: a single struct that
// composes the policy store + the rule catalog + the cross-context
// closures for ActiveHostsLister and CommandInserter into the three
// public interfaces (PolicyService, Lister, RuleProvider).
//
// Policy fan-out (the per-host set_blocklist queue write that follows
// every PUT /api/policy) lives in service.go alongside the
// PolicyService implementation. Enroll-time fan-out is consumed by
// endpoint via PolicyService.ActiveCommandPayload (no per-host queue
// write here -- endpoint handles its own command insert); PUT-time
// fan-out is invoked directly by the operator handler via
// Service.Fanout.
package service
