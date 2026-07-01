package detectionconfig

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/rules/api"
)

// Service is the live detection-config provider. It loads an immutable Snapshot from the Store and swaps it atomically on Reload, so
// rule evaluation (via api.ExclusionResolver) and the detection engine (via api.RuleModeResolver) always read a consistent
// point-in-time view without locks and without a restart. The snapshot is a per-replica cache, safe to lose (ADR-0010): each replica
// converges by reloading. Mutations go through the Service so each one bumps the version (in the store), reloads this replica's
// snapshot, and writes an audit row. Satisfies api.ExclusionResolver and api.RuleModeResolver.
type Service struct {
	store      *Store
	membership Membership
	audit      identityapi.AuditRecorder
	logger     *slog.Logger
	snap       atomic.Pointer[Snapshot]
	// ruleExclusionSupport maps each registered rule id to the exclusion match types it consults (issue #520), injected by bootstrap
	// from the live rule set via SetRuleExclusionSupport. CreateExclusion validates the (rule_id, match_type) pair against it. Nil when
	// unset (non-production constructors / tests), in which case the validation is skipped. Set once during wiring, then read-only, so
	// it needs no synchronization (same posture as audit / membership).
	ruleExclusionSupport map[string][]api.ExclusionMatchType
}

var (
	_ api.ExclusionResolver = (*Service)(nil)
	_ api.RuleModeResolver  = (*Service)(nil)
)

// NewService builds a Service seeded with an empty snapshot (excludes nothing, every rule alerts) so the resolver is safe to consult
// before the first Reload. membership decides whether a group-scoped record applies to a host; nil means only global records apply
// (the Phase A norm, since the only host group is the immutable all-hosts group). audit may be nil (a mutation then drops its audit
// row with a WARN, matching app-control's posture); logger defaults to slog.Default.
func NewService(store *Store, membership Membership, audit identityapi.AuditRecorder, logger *slog.Logger) *Service {
	if store == nil {
		panic("detectionconfig.NewService: store must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &Service{store: store, membership: membership, audit: audit, logger: logger}
	s.snap.Store(NewSnapshot(0, nil, nil, membership, nil))
	return s
}

// SetRuleExclusionSupport injects the per-rule map of exclusion match types the catalog rules consult (issue #520), built by bootstrap
// from the live rule set. CreateExclusion validates the (rule_id, match_type) pair against it so an operator cannot store an exclusion
// a rule would silently ignore, and so a rule_id that names no registered rule is rejected. Set post-construction (mirrors
// SetPrincipalLabelResolver / SetAudit); when left unset the validation is skipped, keeping non-production constructors and the
// store-level tests working. Production always wires it.
func (s *Service) SetRuleExclusionSupport(support map[string][]api.ExclusionMatchType) {
	s.ruleExclusionSupport = support
}

// validateExclusionSupport rejects a create-exclusion request whose rule_id names no registered rule, or whose match_type the target
// rule does not consult (issue #520). A nil support map (never wired) skips the check. Returns ErrInvalidRequest so the handler maps
// it to HTTP 400.
func (s *Service) validateExclusionSupport(in CreateExclusionInput) error {
	if s.ruleExclusionSupport == nil {
		return nil
	}
	supported, ok := s.ruleExclusionSupport[in.RuleID]
	if !ok {
		return fmt.Errorf("%w: rule_id %q does not name a registered rule", ErrInvalidRequest, in.RuleID)
	}
	if len(supported) == 0 {
		return fmt.Errorf("%w: rule %q does not accept exclusions", ErrInvalidRequest, in.RuleID)
	}
	if slices.Contains(supported, in.MatchType) {
		return nil
	}
	return fmt.Errorf("%w: rule %q does not support match_type %q; supported match types: %s",
		ErrInvalidRequest, in.RuleID, in.MatchType, joinMatchTypes(supported))
}

// joinMatchTypes renders a rule's supported match types for the rejection message, in the rule's declared order.
func joinMatchTypes(mts []api.ExclusionMatchType) string {
	parts := make([]string, len(mts))
	for i, mt := range mts {
		parts[i] = string(mt)
	}
	return strings.Join(parts, ", ")
}

// ListExclusions / ListRuleSettings are read passthroughs to the store for the operator surface.
func (s *Service) ListExclusions(ctx context.Context) ([]api.DetectionExclusion, error) {
	return s.store.ListExclusions(ctx)
}

func (s *Service) ListRuleSettings(ctx context.Context) ([]api.DetectionRuleSetting, error) {
	return s.store.ListRuleSettings(ctx)
}

// CreateExclusion persists an exclusion, reloads this replica's snapshot so the change takes effect immediately, and records an audit
// row. The store sets created_by from actor; reason rides the audit payload.
func (s *Service) CreateExclusion(
	ctx context.Context, actor *identityapi.Actor, reason string, in CreateExclusionInput,
) (api.DetectionExclusion, error) {
	in.Actor = actorIdentifier(actor)
	if err := s.validateExclusionSupport(in); err != nil {
		return api.DetectionExclusion{}, err
	}
	excl, err := s.store.CreateExclusion(ctx, in)
	if err != nil {
		return api.DetectionExclusion{}, err
	}
	s.reloadAfterMutation(ctx)
	s.emitAudit(ctx, actor, identityapi.AuditDetectionConfigExclusionCreate, "detection_exclusion",
		strconv.FormatInt(excl.ID, 10), reason, map[string]any{
			"rule_id": excl.RuleID, "match_type": string(excl.MatchType), "value": excl.Value, "host_group_id": excl.HostGroupID,
		})
	return excl, nil
}

// DeleteExclusion removes an exclusion, reloads, and audits. Returns sql.ErrNoRows (via the store) when the id does not exist.
func (s *Service) DeleteExclusion(ctx context.Context, actor *identityapi.Actor, reason string, id int64) error {
	if err := s.store.DeleteExclusion(ctx, id); err != nil {
		return err
	}
	s.reloadAfterMutation(ctx)
	s.emitAudit(ctx, actor, identityapi.AuditDetectionConfigExclusionDelete, "detection_exclusion",
		strconv.FormatInt(id, 10), reason, nil)
	return nil
}

// UpsertRuleSetting sets a rule's per-scope mode / severity override, reloads, and audits.
func (s *Service) UpsertRuleSetting(
	ctx context.Context, actor *identityapi.Actor, reason string, in UpsertSettingInput,
) (api.DetectionRuleSetting, error) {
	in.Actor = actorIdentifier(actor)
	setting, err := s.store.UpsertRuleSetting(ctx, in)
	if err != nil {
		return api.DetectionRuleSetting{}, err
	}
	s.reloadAfterMutation(ctx)
	s.emitAudit(ctx, actor, identityapi.AuditDetectionConfigRuleSettingUpdate, "detection_rule_setting",
		in.RuleID, reason, map[string]any{
			"rule_id": setting.RuleID, "host_group_id": setting.HostGroupID,
			"mode": string(setting.Mode), "severity_override": setting.SeverityOverride,
		})
	return setting, nil
}

// reloadAfterMutation refreshes this replica's snapshot. A failure is logged but does NOT fail the mutation: the write committed and
// bumped the version, so the periodic refresh (or any other replica's read) will converge.
func (s *Service) reloadAfterMutation(ctx context.Context) {
	if err := s.Reload(ctx); err != nil {
		s.logger.WarnContext(ctx, "detectionconfig: snapshot reload after mutation failed; periodic refresh will converge", "err", err)
	}
}

// emitAudit records one operator-action row. Best-effort: a nil recorder or a write failure logs a WARN rather than failing the
// already-committed mutation (the row is durable; the audit row is not on the critical path).
func (s *Service) emitAudit(
	ctx context.Context, actor *identityapi.Actor, action identityapi.AuditAction,
	targetType, targetID, reason string, payload map[string]any,
) {
	if s.audit == nil {
		// No recorder wired (non-production / tests): the mutation still committed, but flag the dropped row so audit loss is
		// visible rather than silent. Production always wires the recorder.
		s.logger.WarnContext(ctx, "detectionconfig: audit recorder not configured; mutation not audited", "action", string(action))
		return
	}
	if payload == nil {
		payload = map[string]any{}
	}
	payload["reason"] = reason
	event := identityapi.AuditEvent{
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		Payload:    payload,
	}
	if actor != nil {
		event.Actor = actor.Principal
	}
	if err := s.audit.Record(ctx, event); err != nil {
		s.logger.WarnContext(ctx, "detectionconfig: audit record failed", "err", err, "action", string(action))
	}
}

// actorIdentifier renders the acting principal id recorded as created_by / actor_email (usr_<id> for a user, svc_<id> for a service
// account). It survives authentication for every actor kind, so a service-account write is attributed rather than rejected by the
// store's required-actor validation (#518). Empty only when there is no actor on the context (a wiring bug). See ADR-0017.
func actorIdentifier(actor *identityapi.Actor) string {
	if actor == nil {
		return ""
	}
	return actor.Principal.ID
}

// Reload reads the current configuration from the store and atomically swaps the in-memory snapshot. Called once at boot (after the
// schema is applied), after every mutation through the REST surface, and by the periodic refresh that picks up another replica's
// changes.
func (s *Service) Reload(ctx context.Context) error {
	snap, err := s.store.LoadSnapshot(ctx, s.membership, nil)
	if err != nil {
		return err
	}
	s.snap.Store(snap)
	return nil
}

// RefreshLoop periodically converges this replica's snapshot with mutations made on OTHER replicas, which only bump the version and
// reload their own snapshot (ADR-0010: the snapshot is a per-replica cache, so a peer's mutation is invisible here until we re-read).
// Each tick reads only the cheap single-row version counter; a full LoadSnapshot runs only when the stored version differs from the
// loaded snapshot's, so a steady state with no config churn is one indexed read per interval. Blocks until ctx is cancelled.
func (s *Service) RefreshLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.refreshTick(ctx) {
				return
			}
		}
	}
}

// refreshTick performs one convergence poll: it reads the cheap version counter and reloads the snapshot when the stored version
// differs from the loaded one (versions are monotonic, so a difference means a peer advanced it). Returns true to stop (ctx cancelled).
func (s *Service) refreshTick(ctx context.Context) (stop bool) {
	current, err := s.store.Version(ctx)
	if err != nil {
		return s.handleRefreshErr(ctx, "version poll", err)
	}
	if current == s.snap.Load().Version() {
		return false
	}
	if err := s.Reload(ctx); err != nil {
		return s.handleRefreshErr(ctx, "reload", err)
	}
	return false
}

// handleRefreshErr decides what a refresh error means: a cancelled context is shutdown racing the poll, so the error is expected and
// the loop stops silently; otherwise it is transient (the next tick retries), so log a WARN and continue.
func (s *Service) handleRefreshErr(ctx context.Context, op string, err error) (stop bool) {
	if ctx.Err() != nil {
		return true
	}
	s.logger.WarnContext(ctx, "detectionconfig: "+op+" failed; retrying next tick", "err", err)
	return false
}

// Excluded implements api.ExclusionResolver against the current snapshot.
func (s *Service) Excluded(ruleID string, matchType api.ExclusionMatchType, value, hostID string) bool {
	return s.snap.Load().Excluded(ruleID, matchType, value, hostID)
}

// ResolveRuleMode implements api.RuleModeResolver against the current snapshot. The single snap.Load() guarantees the engine gets a
// consistent (mode, severity) pair even if a reload swaps the snapshot concurrently.
func (s *Service) ResolveRuleMode(ruleID, hostID string) (api.DetectionRuleMode, string) {
	return s.snap.Load().ResolveRuleMode(ruleID, hostID)
}
