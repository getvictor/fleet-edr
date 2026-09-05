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
	"log/slog"
	"strings"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	rulecontentapi "github.com/fleetdm/edr/server/rulecontent/api"
)

// Service applies attributed changes to rule content.
type Service struct {
	author   rulecontentapi.Author
	validate rulecontentapi.Validator
	audit    identityapi.AuditRecorder
	logger   *slog.Logger
}

// New builds a Service. The author and validator are required; the recorder is not, because the non-production wirings that
// construct this without one still need the mutations to work. What a missing recorder costs is spelled out at the call site
// below, where the row is dropped.
func New(
	author rulecontentapi.Author, validate rulecontentapi.Validator,
	audit identityapi.AuditRecorder, logger *slog.Logger,
) (*Service, error) {
	if author == nil || validate == nil {
		return nil, errors.New("rule authoring: an author and a validator are both required")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{author: author, validate: validate, audit: audit, logger: logger}, nil
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
	version, warnings, err := s.author.Put(ctx, doc)
	if err != nil {
		return 0, warnings, err
	}
	s.record(ctx, actor, reason, identityapi.AuditRuleContentDocumentPut, doc.Path, version, warnings)
	return version, warnings, nil
}

// Delete removes a document and records the change against actor.
func (s *Service) Delete(
	ctx context.Context, actor *identityapi.Actor, reason string, path string,
) (int64, []string, error) {
	if strings.TrimSpace(reason) == "" {
		return 0, nil, ErrReasonRequired
	}
	version, warnings, err := s.author.Delete(ctx, path)
	if err != nil {
		return 0, warnings, err
	}
	s.record(ctx, actor, reason, identityapi.AuditRuleContentDocumentDelete, path, version, warnings)
	return version, warnings, nil
}

// Check reports what submitting doc would do, without doing it.
//
// Not audited, and that is not an oversight: nothing happened to the thing being audited. It is also why this takes no reason.
// An operator checking their work before publishing has nothing to justify yet.
func (s *Service) Check(ctx context.Context, doc rulecontentapi.Document) ([]string, error) {
	return s.validate.Validate(ctx, []rulecontentapi.Document{doc})
}

// record writes the audit row for a change that took effect.
//
// Synchronous, following the AuditRecorder contract: this is a write action, so a row that is still in flight when the process
// dies is not a useful trail. A failure is logged rather than returned, because the change is already durable and telling the
// operator it failed would be false; the log line is what a reviewer finding a gap in the trail has to work from.
func (s *Service) record(
	ctx context.Context, actor *identityapi.Actor, reason string,
	action identityapi.AuditAction, docPath string, version int64, warnings []string,
) {
	if s.audit == nil {
		// No recorder wired (non-production and tests). The mutation is committed either way, so the honest thing is to say a row
		// was lost rather than to pretend one was written.
		s.logger.WarnContext(ctx, "rule content change not audited: no recorder is wired",
			"action", string(action), "document", docPath)
		return
	}
	payload := map[string]any{
		"reason":         reason,
		"corpus_version": version,
	}
	if len(warnings) > 0 {
		// Recorded because a warning is the operator being told their rule will not fire, and a reviewer asking why a detection
		// never matched wants to know that was said at the time rather than discovering it later.
		payload["warnings"] = warnings
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
	if err := s.audit.Record(ctx, e); err != nil {
		s.logger.ErrorContext(ctx, "rule content change committed but its audit row was not written",
			"err", err, "action", string(action), "document", docPath)
	}
}
