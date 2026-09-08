package ruleauthoring

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	rulecontentapi "github.com/fleetdm/edr/server/rulecontent/api"
)

// PackService is the pack lifecycle with an actor, a reason and an audit row attached.
//
// Separate from Service beside it because the two operate on different nouns: that one changes individual rule documents, this
// one replaces every shipped rule at once. Sharing a type would mean one audit target type for two very different blast radii.
//
// It adds nothing to reading status, which changes nothing and needs no reason, so that method is a pass-through. The asymmetry
// is deliberate: a reason is required exactly where something is being changed.
type PackService struct {
	packs  rulecontentapi.PackLifecycle
	drain  *AuditDrain
	logger *slog.Logger
}

// NewPackService builds a PackService. Every collaborator is required, the recorder included: a rollback that replaced every
// shipped rule without leaving an audit row is the one change here least acceptable to lose.
func NewPackService(
	packs rulecontentapi.PackLifecycle, outbox rulecontentapi.AuditOutbox,
	audit identityapi.AuditRecorder, logger *slog.Logger,
) (*PackService, error) {
	if packs == nil || audit == nil {
		return nil, errors.New("rule pack service: a pack lifecycle and an audit recorder are both required")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	drain, err := NewAuditDrain(outbox, audit, logger)
	if err != nil {
		return nil, err
	}
	return &PackService{packs: packs, drain: drain, logger: logger}, nil
}

// Status reports which generation of shipped rules is installed and how it differs from the one this build carries.
func (s *PackService) Status(ctx context.Context) (rulecontentapi.PackStatus, error) {
	return s.packs.Status(ctx)
}

// Rollback restores the generation the last install replaced, and records who did it and why.
//
// The reason is required, as it is for every other change to rule content. This one is the strongest case for it: the change
// swaps out every shipped detection a deployment runs, so an entry saying only that it happened would be the least useful of the
// set.
func (s *PackService) Rollback(
	ctx context.Context, actor *identityapi.Actor, reason string,
) (rulecontentapi.PackRollback, error) {
	if strings.TrimSpace(reason) == "" {
		return rulecontentapi.PackRollback{}, ErrReasonRequired
	}
	// The audit entry is built from the rollback's own result and written in the transaction that performs it (issue #886), so
	// the two commit together. It used to be written afterwards, with a failure logged rather than returned, which left a window
	// in which every shipped rule changed durably and nothing named who did it. That was the lesser of the two outcomes then
	// available, since returning the error would have reported failure for a change that had already happened; the outbox is
	// what makes a third outcome available.
	rolled, err := s.packs.Rollback(ctx, func(r rulecontentapi.PackRollback) (rulecontentapi.AuditOutboxEntry, error) {
		payload := map[string]any{
			"reason":         reason,
			"restored_pack":  r.Restored,
			"corpus_version": r.Version,
		}
		if len(r.Withheld) > 0 {
			// Recorded because the deployment is deliberately not running shipped rules it was offered, and a reviewer asking
			// why a detection is absent wants that visible at the point the decision was made.
			payload["withheld"] = r.Withheld
		}
		e := identityapi.AuditEvent{
			Action:     identityapi.AuditRuleContentPackRollback,
			TargetType: "rule_content_pack",
			TargetID:   r.Restored,
			Payload:    payload,
		}
		if actor != nil {
			e.Actor = actor.Principal
		}
		return encodeAuditEntry(e)
	})
	if err != nil {
		// Not audited: nothing happened to the thing being audited. A refused rollback leaves the corpus exactly as it was, and
		// a builder error fails the rollback rather than completing it unrecorded.
		return rulecontentapi.PackRollback{}, err
	}
	s.deliver(ctx)
	return rolled, nil
}

// deliver turns the entry this rollback just committed into an audit row, now rather than on the next sweep. Best effort: the
// entry is already durable, so a failure delays the row rather than losing it.
func (s *PackService) deliver(ctx context.Context) {
	if s.drain == nil {
		return
	}
	if _, err := s.drain.Drain(ctx); err != nil {
		s.logger.WarnContext(ctx, "rule pack audit entry is committed but not yet delivered; the sweep will retry it",
			"err", err)
	}
}
