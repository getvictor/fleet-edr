package ruleauthoring

import (
	"context"
	"log/slog"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	rulecontentapi "github.com/fleetdm/edr/server/rulecontent/api"
	"github.com/fleetdm/edr/server/rules/internal/auditoutbox"
)

// encodeAuditEntry encodes an audit event as the opaque entry rulecontent stores alongside the content change (issue #886).
func encodeAuditEntry(e identityapi.AuditEvent) (rulecontentapi.AuditOutboxEntry, error) {
	entry, err := auditoutbox.Encode(e)
	return rulecontentapi.AuditOutboxEntry{Kind: entry.Kind, Payload: entry.Payload}, err
}

// NewAuditDrain builds the drain for rulecontent's audit outbox.
func NewAuditDrain(
	outbox rulecontentapi.AuditOutbox, audit identityapi.AuditRecorder, logger *slog.Logger,
) (*auditoutbox.Drain, error) {
	var adapted auditoutbox.Outbox
	if outbox != nil {
		adapted = ruleContentOutbox{inner: outbox}
	}
	return auditoutbox.NewDrain(adapted, audit, "rule content", logger)
}

// ruleContentOutbox presents rulecontent's outbox, whose types are declared in rulecontent's API, as the drain's Outbox.
type ruleContentOutbox struct{ inner rulecontentapi.AuditOutbox }

func (o ruleContentOutbox) PendingAuditEntries(ctx context.Context, limit int) ([]auditoutbox.Pending, error) {
	entries, err := o.inner.PendingAuditEntries(ctx, limit)
	if err != nil {
		return nil, err
	}
	out := make([]auditoutbox.Pending, len(entries))
	for i, e := range entries {
		out[i] = auditoutbox.Pending{ID: e.ID, Kind: e.Kind, Payload: e.Payload}
	}
	return out, nil
}

func (o ruleContentOutbox) DeleteAuditEntries(ctx context.Context, ids []int64) error {
	return o.inner.DeleteAuditEntries(ctx, ids)
}
