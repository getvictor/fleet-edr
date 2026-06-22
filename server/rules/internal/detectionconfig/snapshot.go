package detectionconfig

import (
	"time"

	"github.com/fleetdm/edr/server/rules/api"
)

// Membership reports whether hostID belongs to the host group groupID. The snapshot calls it to decide whether a group-scoped record
// applies to a host. A nil Membership means "only global records apply" (the safe default before editable host groups exist).
// Bootstrap wires this to the host-group resolver; in Phase A the only group is the seeded all-hosts group, whose membership is every
// enrolled host.
type Membership func(hostID string, groupID int64) bool

// exclKey indexes exclusions by (rule, match type) so a lookup touches only the handful of entries for that key rather than scanning
// the whole allowlist.
type exclKey struct {
	ruleID    string
	matchType api.ExclusionMatchType
}

type exclEntry struct {
	value       string
	hostGroupID int64
	expiresAt   *time.Time
}

type settingEntry struct {
	hostGroupID int64
	mode        api.DetectionRuleMode
	severity    string
}

// Snapshot is an immutable in-memory view of the detection configuration at a given version. It satisfies api.ExclusionResolver and
// api.RuleModeResolver. Construct it with NewSnapshot; never mutate after construction (it is read concurrently by rule evaluation).
type Snapshot struct {
	version    int64
	exclusions map[exclKey][]exclEntry
	settings   map[string][]settingEntry
	membership Membership
	now        func() time.Time
}

var (
	_ api.ExclusionResolver = (*Snapshot)(nil)
	_ api.RuleModeResolver  = (*Snapshot)(nil)
)

// NewSnapshot builds a snapshot from already-loaded rows. The store calls it; tests call it directly to exercise resolution without a
// database. A nil clock defaults to time.Now (used only for exclusion expiry).
func NewSnapshot(
	version int64, exclusions []api.DetectionExclusion, settings []api.DetectionRuleSetting,
	membership Membership, clock func() time.Time,
) *Snapshot {
	if clock == nil {
		clock = time.Now
	}
	s := &Snapshot{
		version:    version,
		exclusions: make(map[exclKey][]exclEntry, len(exclusions)),
		settings:   make(map[string][]settingEntry),
		membership: membership,
		now:        clock,
	}
	for _, e := range exclusions {
		if !e.Enabled {
			continue
		}
		k := exclKey{ruleID: e.RuleID, matchType: e.MatchType}
		s.exclusions[k] = append(s.exclusions[k], exclEntry{value: e.Value, hostGroupID: e.HostGroupID, expiresAt: e.ExpiresAt})
	}
	for _, st := range settings {
		s.settings[st.RuleID] = append(s.settings[st.RuleID], settingEntry{
			hostGroupID: st.HostGroupID, mode: st.Mode, severity: st.SeverityOverride,
		})
	}
	return s
}

// Version returns the config version this snapshot was loaded at.
func (s *Snapshot) Version() int64 { return s.version }

// scopeApplies reports whether a record scoped to hostGroupID applies to hostID: global records always apply; a group-scoped record
// applies only when the host is a member of that group.
func (s *Snapshot) scopeApplies(hostGroupID int64, hostID string) bool {
	if hostGroupID == api.GlobalScope {
		return true
	}
	return s.membership != nil && s.membership(hostID, hostGroupID)
}

// Excluded implements api.ExclusionResolver. It checks rule-specific entries and shared (rule_id == "") entries for the match type,
// returning true on the first applicable, unexpired entry whose value matches.
func (s *Snapshot) Excluded(ruleID string, matchType api.ExclusionMatchType, value, hostID string) bool {
	if s.matchAny(ruleID, matchType, value, hostID) {
		return true
	}
	return ruleID != "" && s.matchAny("", matchType, value, hostID)
}

func (s *Snapshot) matchAny(ruleID string, matchType api.ExclusionMatchType, value, hostID string) bool {
	now := s.now()
	for _, e := range s.exclusions[exclKey{ruleID: ruleID, matchType: matchType}] {
		if e.expiresAt != nil && !e.expiresAt.After(now) {
			continue
		}
		if !s.scopeApplies(e.hostGroupID, hostID) {
			continue
		}
		if api.MatchExclusionValue(matchType, e.value, value) {
			return true
		}
	}
	return false
}

// ResolveRuleMode implements api.RuleModeResolver: it resolves the winning setting for (ruleID, hostID) ONCE and returns both the
// mode and the severity override, so the engine never observes a mode from one snapshot and a severity from another.
func (s *Snapshot) ResolveRuleMode(ruleID, hostID string) (api.DetectionRuleMode, string) {
	w, ok := s.winning(ruleID, hostID)
	if !ok {
		return api.DetectionRuleModeAlert, ""
	}
	mode := w.mode
	if !api.IsValidDetectionRuleMode(mode) {
		mode = api.DetectionRuleModeAlert
	}
	return mode, w.severity
}

// Mode reports the resolved mode for (ruleID, hostID). Retained for direct snapshot unit tests; the engine path goes through
// ResolveRuleMode.
func (s *Snapshot) Mode(ruleID, hostID string) api.DetectionRuleMode {
	mode, _ := s.ResolveRuleMode(ruleID, hostID)
	return mode
}

// SeverityOverride reports the resolved severity override for (ruleID, hostID), or "" when none applies. Retained for direct
// snapshot unit tests.
func (s *Snapshot) SeverityOverride(ruleID, hostID string) string {
	_, severity := s.ResolveRuleMode(ruleID, hostID)
	return severity
}

// winning returns the most-specific setting entry that applies to hostID: a group-scoped entry beats the global entry. When several
// group entries apply (a host in multiple groups, not possible in Phase A) the smallest group id wins, for determinism.
func (s *Snapshot) winning(ruleID, hostID string) (settingEntry, bool) {
	var best settingEntry
	found := false
	for _, e := range s.settings[ruleID] {
		if !s.scopeApplies(e.hostGroupID, hostID) {
			continue
		}
		if !found || moreSpecific(e, best) {
			best = e
			found = true
		}
	}
	return best, found
}

// moreSpecific reports whether candidate outranks current: any group scope beats global; between two group scopes the smaller id wins.
func moreSpecific(candidate, current settingEntry) bool {
	if current.hostGroupID == api.GlobalScope {
		return candidate.hostGroupID != api.GlobalScope
	}
	if candidate.hostGroupID == api.GlobalScope {
		return false
	}
	return candidate.hostGroupID < current.hostGroupID
}
