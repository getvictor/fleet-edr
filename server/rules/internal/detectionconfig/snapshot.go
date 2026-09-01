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
	_ api.ExclusionResolver      = (*Snapshot)(nil)
	_ api.RuleModeResolver       = (*Snapshot)(nil)
	_ api.GlobalRuleModeResolver = (*Snapshot)(nil)
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
//
// A setting always wins over ruleDefault, and that ordering is the point of the parameter rather than an implementation detail: an
// operator who promotes a rule must not be overridden by the rule's own opinion of how it should run.
//
// ruleDefault is also what an UNINTERPRETABLE stored mode falls back to, where this used to fall back to alerting. A stored value
// this build does not recognise is not an instruction to alert; it is not an instruction at all. Falling back to alert would take a
// rule whose author declared monitor and promote it on the strength of a value we could not read, which is the one outcome the
// declared default exists to prevent. The severity override is still honoured, because it is legible even when the mode is not.
func (s *Snapshot) ResolveRuleMode(ruleID, hostID string, ruleDefault api.DetectionRuleMode) (api.DetectionRuleMode, string) {
	mode, severity, _ := s.resolveMode(ruleID, hostID, ruleDefault)
	return mode, severity
}

// GlobalRuleMode implements api.GlobalRuleModeResolver: the mode ruleID runs in at global scope, and whether a setting or the rule's
// own declaration produced it.
//
// The empty host id is what makes this global rather than a per-host resolution: scopeApplies admits a globally scoped setting for
// any host and a group-scoped one only for a member, and no host is a member of anything.
//
// A setting whose stored mode this build cannot interpret reports source `default`, because that is where the mode being reported
// came from. Calling it `setting` would tell an operator the mode they are looking at is one they chose, when it is the fallback
// standing in for a value we could not read.
func (s *Snapshot) GlobalRuleMode(ruleID string, ruleDefault api.DetectionRuleMode) api.GlobalRuleMode {
	w, ok := s.winningGlobal(ruleID)
	mode, _, source := applySetting(w, ok, ruleDefault)
	return api.GlobalRuleMode{Mode: mode, Source: source}
}

// resolveMode resolves the mode for a HOST and reports where it came from.
func (s *Snapshot) resolveMode(
	ruleID, hostID string, ruleDefault api.DetectionRuleMode,
) (api.DetectionRuleMode, string, api.RuleModeSource) {
	w, ok := s.winning(ruleID, hostID)
	return applySetting(w, ok, ruleDefault)
}

// applySetting is the one place the setting-versus-default fallback lives, so a per-host resolution and a global one cannot answer
// the same question differently. It reports the winning severity override alongside, since a setting carries one even when its mode
// is unreadable, and the source, since a caller reporting the mode to an operator has to say which of the two produced it.
func applySetting(w settingEntry, ok bool, ruleDefault api.DetectionRuleMode) (api.DetectionRuleMode, string, api.RuleModeSource) {
	if !ok {
		return ruleDefault, "", api.RuleModeSourceDefault
	}
	if !api.IsValidDetectionRuleMode(w.mode) {
		return ruleDefault, w.severity, api.RuleModeSourceDefault
	}
	return w.mode, w.severity, api.RuleModeSourceSetting
}

// Mode reports the resolved mode for (ruleID, hostID) against a rule that declares no default. Retained for direct snapshot unit
// tests; the engine path goes through ResolveRuleMode with the rule's own default.
func (s *Snapshot) Mode(ruleID, hostID string) api.DetectionRuleMode {
	mode, _ := s.ResolveRuleMode(ruleID, hostID, api.DetectionRuleModeAlert)
	return mode
}

// SeverityOverride reports the resolved severity override for (ruleID, hostID), or "" when none applies. Retained for direct
// snapshot unit tests.
func (s *Snapshot) SeverityOverride(ruleID, hostID string) string {
	_, severity := s.ResolveRuleMode(ruleID, hostID, api.DetectionRuleModeAlert)
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

// winningGlobal returns the globally scoped setting for ruleID, ignoring every group-scoped one.
//
// Written as its own walk rather than winning(ruleID, "") on the reasoning that no host belongs to a group. That reasoning routes
// the answer through the membership function, which is supplied by the caller and free to say anything about a host id it has
// never seen: a membership that admits an unknown host to a group would let a group-scoped setting decide a question that is
// supposed to be global. Selecting on the scope itself makes it global by construction instead of by trusting a collaborator.
//
// The global entry is unique per rule (uk_detection_rule_settings_rule_scope), so the first match is the only one.
func (s *Snapshot) winningGlobal(ruleID string) (settingEntry, bool) {
	for _, e := range s.settings[ruleID] {
		if e.hostGroupID == api.GlobalScope {
			return e, true
		}
	}
	return settingEntry{}, false
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
