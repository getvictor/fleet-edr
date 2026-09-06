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
	audit  identityapi.AuditRecorder
	logger *slog.Logger
}

// NewPackService builds a PackService. Every collaborator is required, the recorder included: a rollback that replaced every
// shipped rule without leaving an audit row is the one change here least acceptable to lose.
func NewPackService(
	packs rulecontentapi.PackLifecycle, audit identityapi.AuditRecorder, logger *slog.Logger,
) (*PackService, error) {
	if packs == nil || audit == nil {
		return nil, errors.New("rule pack service: a pack lifecycle and an audit recorder are both required")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &PackService{packs: packs, audit: audit, logger: logger}, nil
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
	rolled, err := s.packs.Rollback(ctx)
	if err != nil {
		// Not audited: nothing happened to the thing being audited. A refused rollback leaves the corpus exactly as it was.
		return rulecontentapi.PackRollback{}, err
	}

	payload := map[string]any{
		"reason":         reason,
		"restored_pack":  rolled.Restored,
		"corpus_version": rolled.Version,
	}
	if len(rolled.Withheld) > 0 {
		// Recorded because the deployment is deliberately not running shipped rules it was offered, and a reviewer asking why a
		// detection is absent wants that visible at the point the decision was made.
		payload["withheld"] = rolled.Withheld
	}
	e := identityapi.AuditEvent{
		Action:     identityapi.AuditRuleContentPackRollback,
		TargetType: "rule_content_pack",
		TargetID:   rolled.Restored,
		Payload:    payload,
	}
	if actor != nil {
		e.Actor = actor.Principal
	}
	if err := s.audit.Record(ctx, e); err != nil {
		s.logger.ErrorContext(ctx, "rule pack rollback committed but its audit row was not written",
			"err", err, "pack", rolled.Restored)
	}
	return rolled, nil
}
