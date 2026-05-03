package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/policy"
)

// ActiveHostsLister enumerates host_ids the policy fan-out should
// target. Closure-typed so cmd/main can supply a late-bound
// implementation that resolves endpoint.Service() at call time without
// rules taking a hard interface dependency on endpoint.
type ActiveHostsLister func(ctx context.Context) ([]string, error)

// CommandInserter inserts a single command row keyed on host_id.
// Closure-typed for the same reason as ActiveHostsLister; today
// cmd/main supplies response/api.Service.Insert as a method value.
type CommandInserter func(ctx context.Context, hostID, commandType string, payload []byte) (int64, error)

// Service is the rules orchestrator. A single struct satisfies all
// three public api interfaces (PolicyService, Lister, RuleProvider).
type Service struct {
	policy *policy.Store
	rules  []api.Rule
	hosts  ActiveHostsLister
	cmds   CommandInserter
	logger *slog.Logger
}

// New builds a Service. policyStore must be non-nil; the rule slice
// may be empty (zero-rule deployments are unusual but accepted, e.g.
// the docs-generator path that asks for the catalog without running
// rules). hosts + cmds must be both nil or both non-nil; an asymmetric
// pair makes the fan-out path silently broken.
func New(
	policyStore *policy.Store,
	rules []api.Rule,
	hosts ActiveHostsLister,
	cmds CommandInserter,
	logger *slog.Logger,
) *Service {
	if policyStore == nil {
		panic("rules service.New: policy store must not be nil")
	}
	if (hosts == nil) != (cmds == nil) {
		panic("rules service.New: ActiveHostsLister and CommandInserter must both be set or both nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if rules == nil {
		rules = []api.Rule{}
	}
	return &Service{
		policy: policyStore,
		rules:  rules,
		hosts:  hosts,
		cmds:   cmds,
		logger: logger,
	}
}

// --- api.PolicyService ---------------------------------------------------------

// Get returns the active default policy.
func (s *Service) Get(ctx context.Context) (api.BlocklistPolicy, error) {
	return s.policy.Get(ctx, api.DefaultPolicyName)
}

// Update mutates the active default policy. Validation errors
// (ErrInvalidPath, ErrInvalidHash, ErrInvalidUpdateRequest) are
// returned wrapped so callers can errors.Is + map to 400.
func (s *Service) Update(ctx context.Context, req api.UpdateRequest) (api.BlocklistPolicy, error) {
	if req.Name == "" {
		req.Name = api.DefaultPolicyName
	}
	return s.policy.Update(ctx, req)
}

// ActiveCommandPayload returns the active policy already marshaled
// as a set_blocklist command payload. hasContent is false when the
// blocklist is empty so callers (notably endpoint's enroll fan-out)
// can skip the per-host command insert.
func (s *Service) ActiveCommandPayload(ctx context.Context) (json.RawMessage, int64, bool, error) {
	p, err := s.Get(ctx)
	if err != nil {
		// Treat ErrPolicyNotFound as "no content yet" rather than an
		// error: the seed insert hasn't fired (fresh schema), so the
		// agent has nothing to apply. The caller should not retry.
		if errors.Is(err, api.ErrPolicyNotFound) {
			return nil, 0, false, nil
		}
		return nil, 0, false, fmt.Errorf("rules: load active policy: %w", err)
	}
	if len(p.Blocklist.Paths) == 0 && len(p.Blocklist.Hashes) == 0 {
		return nil, p.Version, false, nil
	}
	payload, err := api.MarshalSetBlocklistPayload(p)
	if err != nil {
		return nil, p.Version, false, fmt.Errorf("rules: marshal active policy command payload: %w", err)
	}
	return payload, p.Version, true, nil
}

// --- api.Lister + api.RuleProvider --------------------------------------------

// List returns RuleMetadata in registration order. Used by the
// operator endpoints (/api/rules, /api/attack-coverage) and the docs
// generator.
func (s *Service) List() []api.RuleMetadata {
	out := make([]api.RuleMetadata, 0, len(s.rules))
	for _, r := range s.rules {
		out = append(out, api.RuleMetadata{
			ID:         r.ID(),
			Techniques: r.Techniques(),
			Doc:        r.Doc(),
		})
	}
	return out
}

// ActiveRules returns the in-memory rule set, identical to the
// constructor input. Hot-reload is a future extension point.
func (s *Service) ActiveRules() []api.Rule {
	return s.rules
}

// --- Fan-out -------------------------------------------------------------------

// Fanout pushes a freshly-updated policy to every active host as a
// set_blocklist command. Returns:
//   - totalHosts: count of active hosts targeted (0 when fan-out
//     skipped because the operator surface is disabled or the
//     blocklist is empty; also 0 when host-listing fails before
//     any insert is attempted).
//   - failedHosts: count of hosts whose command insert failed.
//   - err: a fatal pre-loop error (marshal failure, host-list
//     failure). A nil err with failedHosts > 0 means partial
//     fan-out -- the policy row is authoritative and operators
//     surface the count via the audit log + span attribute.
//
// Best-effort: a partial failure does NOT undo the policy update --
// the policy row is authoritative and the next poll/admin push
// catches up.
//
// Returns (0, 0, nil) when the operator surface is disabled
// (hosts/cmds closures nil) or when the blocklist has no content
// (skip per PolicyService.ActiveCommandPayload semantics).
func (s *Service) Fanout(ctx context.Context, p api.BlocklistPolicy) (totalHosts, failedHosts int, err error) {
	if s.hosts == nil || s.cmds == nil {
		return 0, 0, nil
	}
	if len(p.Blocklist.Paths) == 0 && len(p.Blocklist.Hashes) == 0 {
		return 0, 0, nil
	}
	payload, err := api.MarshalSetBlocklistPayload(p)
	if err != nil {
		return 0, 0, fmt.Errorf("rules fanout: marshal payload: %w", err)
	}
	hostIDs, err := s.hosts(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("rules fanout: list active hosts: %w", err)
	}
	totalHosts = len(hostIDs)
	for _, hostID := range hostIDs {
		if _, insErr := s.cmds(ctx, hostID, api.CommandTypeSetBlocklist, payload); insErr != nil {
			failedHosts++
			s.logger.WarnContext(ctx, "rules policy fan-out failed",
				attrkeys.HostID, hostID, "err", insErr)
		}
	}
	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.SetAttributes(
			attribute.Int64("edr.policy.version", p.Version),
			attribute.Int("edr.policy.fanout_hosts", totalHosts),
			attribute.Int("edr.policy.fanout_failed", failedHosts),
		)
	}
	return totalHosts, failedHosts, nil
}
