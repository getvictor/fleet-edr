// Package ruleauthoring is the governed side of rule-content authoring: who changed what, why, and the record of it.
//
// It sits between the operator handler and rulecontent's authoring lifecycle, and exists because the two halves cannot be in one
// place. rulecontent owns the corpus and the validate-then-write ordering, and imports no other context's api (ADR-0021), so it
// cannot reach the audit recorder. The handler could, but audit belongs beside the decision it records rather than beside the
// parsing of a request, which is also where detectionconfig puts it.
package ruleauthoring

import (
	"context"
	"errors"
	"strings"

	"github.com/fleetdm/edr/server/auditoutbox"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	rulecontentapi "github.com/fleetdm/edr/server/rulecontent/api"
)

// Service applies attributed changes to rule content.
type Service struct {
	author   rulecontentapi.Author
	validate rulecontentapi.Validator
	drain    *auditoutbox.Drain
}

// New builds a Service. Every collaborator is required, the drain included.
//
// An earlier revision let the audit recorder be nil and logged the dropped row, on the theory that a non-production wiring still
// needs the mutations to work. Review pointed out what that actually buys: the caller mounts these routes whenever an author and a
// corpus are present, so a wiring with nothing to record through is a reachable state in which every successful change to what a
// fleet detects loses its audit row. "Every authoring change is attributable" is a contract the outbox introduced, and a
// construction that can silently violate it is not a convenience.
//
// The drain is passed in rather than built here, and it is the one the rules context sweeps. A service that built its own would ask
// an instance nothing runs, and since a change asks for delivery rather than performing it (issue #1089), its audit row would then
// wait for the sweep's next interval instead of being written at once. That is not hypothetical: it is how this was wired, and the
// cross-context authoring test is what caught it.
//
// No logger, because the drain carries the one its failures are reported through and this service reports none of its own.
func New(author rulecontentapi.Author, validate rulecontentapi.Validator, drain *auditoutbox.Drain) (*Service, error) {
	if author == nil || validate == nil || drain == nil {
		return nil, errors.New("rule authoring: an author, a validator and an audit drain are all required")
	}
	return &Service{author: author, validate: validate, drain: drain}, nil
}

// ErrReasonRequired reports that a change arrived without a stated reason.
//
// Refused rather than defaulted, because the reason is the only field in the audit row that says WHY. A blank one leaves a trail
// that records who changed what and is silent on the question a reviewer is actually asking.
var ErrReasonRequired = errors.New("rule authoring: a reason is required")

// Put writes a document and records the change against actor.
//
// The audit row is written AFTER the change takes effect, and only then. A refused submission did not alter the corpus, so
// recording it as a mutation would make the trail disagree with the thing it audits: the operator gets the refusal and its
// reason, and an authorization denial is already recorded by the chokepoint.
func (s *Service) Put(
	ctx context.Context, actor *identityapi.Actor, reason string, doc rulecontentapi.Document,
) (int64, []string, error) {
	if strings.TrimSpace(reason) == "" {
		return 0, nil, ErrReasonRequired
	}
	version, found, err := s.author.Put(ctx, doc, s.auditEntry(actor, reason, identityapi.AuditRuleContentDocumentPut, doc.Path))
	// Flattened to messages here, and this is the right boundary for it. The lifecycle narrowed the findings to the document
	// under change, so the path is no longer carrying information: both consumers downstream, the HTTP response and the audit
	// row, are already about that one document.
	warnings := rulecontentapi.WarningMessages(found)
	if err != nil {
		return 0, warnings, err
	}
	s.deliver(ctx)
	return version, warnings, nil
}

// Delete removes a document and records the change against actor.
func (s *Service) Delete(
	ctx context.Context, actor *identityapi.Actor, reason string, path string,
) (int64, []string, error) {
	if strings.TrimSpace(reason) == "" {
		return 0, nil, ErrReasonRequired
	}
	version, found, err := s.author.Delete(ctx, path, s.auditEntry(actor, reason, identityapi.AuditRuleContentDocumentDelete, path))
	warnings := rulecontentapi.WarningMessages(found)
	if err != nil {
		return 0, warnings, err
	}
	s.deliver(ctx)
	return version, warnings, nil
}

// Check reports what submitting doc would do, without doing it.
//
// Not audited, and that is not an oversight: nothing happened to the thing being audited. It is also why this takes no reason.
// An operator checking their work before publishing has nothing to justify yet.
func (s *Service) Check(ctx context.Context, doc rulecontentapi.Document) ([]string, error) {
	// A check validates the submitted document ALONE rather than the corpus it would join, so every finding is already about it
	// and there is nothing to narrow. That is also why a check cannot report a collision with the stored corpus: it answers "is
	// this document itself loadable", and Put answers the corpus question.
	found, err := s.validate.Validate(ctx, []rulecontentapi.Document{doc})
	return rulecontentapi.WarningMessages(found), err
}

// auditEntry returns the builder rulecontent calls inside the transaction that makes the change (issue #886).
//
// The audit row used to be written AFTER that transaction committed, and a failure was logged rather than returned. The ordering
// was the lesser of two bad outcomes rather than an oversight: returning the error would report failure for a change that had
// already happened. It still left a window in which a fleet's detections changed and nothing named who did it or why.
//
// A builder rather than a value because the facts worth recording, the version the change produces and the warnings narrowed to
// this document, are computed inside that call. Passing an entry in would mean either duplicating that logic here or recording a
// weaker row than the one this replaces.
func (s *Service) auditEntry(
	actor *identityapi.Actor, reason string, action identityapi.AuditAction, docPath string,
) rulecontentapi.AuditEntryFunc {
	return func(version int64, warnings []rulecontentapi.ContentWarning) (rulecontentapi.AuditOutboxEntry, error) {
		payload := map[string]any{
			"reason":         reason,
			"corpus_version": version,
		}
		if messages := rulecontentapi.WarningMessages(warnings); len(messages) > 0 {
			// Recorded because a warning is the operator being told their rule will not fire, and a reviewer asking why a
			// detection never matched wants to know that was said at the time rather than discovering it later.
			payload["warnings"] = messages
		}
		e := identityapi.AuditEvent{
			Action:     action,
			TargetType: "rule_content_document",
			TargetID:   docPath,
			Payload:    payload,
		}
		if actor != nil {
			e.Actor = actor.Principal
		}
		return encodeAuditEntry(e)
	}
}

// deliver asks the sweep for the entry this change just committed, rather than leaving it to the next interval.
//
// Nothing is waited on, and nothing is reported, which is the whole point of the outbox: the entry is already durable, committed
// with the change, so a delivery that fails or is slow delays the audit row rather than losing it, and the sweep retries it. Failing
// the caller on it would be the false report the ordering was chosen to avoid, and waiting for it would put a change that already
// succeeded behind the audit store (issue #1089).
func (s *Service) deliver(ctx context.Context) {
	s.drain.DeliverSoon(ctx)
}
