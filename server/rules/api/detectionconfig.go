package api

import (
	"strings"
	"time"
)

// --- Detection configuration surface (issue #459) ----------------------------
//
// DB-backed replacement for the boot-time env-CSV allowlists + disabled-rule list. Two layers, mirroring industry practice (Falcon /
// Defender / SentinelOne / Elastic): per-rule settings (mode + severity override + future JSON settings) and typed exclusions (the
// allowlist layer). Both are scopable to a host group (or global) and resolved PER HOST at evaluation time. These types live on the
// rules.api surface so catalog rules consume the resolver interfaces without importing the rules-internal detectionconfig package.

// DetectionRuleMode is the per-(rule, scope) operating mode. Three values, the shape every major EDR converged on (Defender ASR audit
// mode, Falcon detect-vs-prevent, SentinelOne rule states):
//
//   - alert:    the rule produces alerts as normal (the default when unset).
//   - monitor:  the rule still evaluates, but a match emits an observability signal instead of persisting an alert, so an operator can
//     gauge a rule's noise before promoting it to alert.
//   - disabled: the rule produces nothing for the scope.
type DetectionRuleMode string

const (
	DetectionRuleModeAlert    DetectionRuleMode = "alert"
	DetectionRuleModeMonitor  DetectionRuleMode = "monitor"
	DetectionRuleModeDisabled DetectionRuleMode = "disabled"
)

// IsValidDetectionRuleMode reports whether m is one of the defined modes. Used at the REST boundary to reject untrusted input before it
// reaches the store.
func IsValidDetectionRuleMode(m DetectionRuleMode) bool {
	switch m {
	case DetectionRuleModeAlert, DetectionRuleModeMonitor, DetectionRuleModeDisabled:
		return true
	}
	return false
}

// ExclusionMatchType is the dimension a detection exclusion keys on. Typed (never free-form), and deliberately NOT keyed on IP/ASN for
// shared CDNs (the best-practice note on suspicious_exec, and the industry guidance from Falcon and Defender). The four legacy
// allowlists map onto a subset: launchagent -> path_glob, launchdaemon -> team_id, sudoers -> path_glob, suspicious_exec ->
// parent_path_glob.
type ExclusionMatchType string

const (
	// ExclusionMatchPathGlob matches an absolute filesystem path against a glob where `*` matches any run of characters including `/`
	// (a pattern with no `*` is an exact match). Used for the executable / writer / plist path.
	ExclusionMatchPathGlob ExclusionMatchType = "path_glob"
	// ExclusionMatchParentPathGlob is path_glob applied to a chain's non-shell parent path (suspicious_exec).
	ExclusionMatchParentPathGlob ExclusionMatchType = "parent_path_glob"
	// ExclusionMatchTeamID matches an Apple Developer team ID exactly.
	ExclusionMatchTeamID ExclusionMatchType = "team_id"
	// ExclusionMatchSigningID matches a code-signing identifier exactly.
	ExclusionMatchSigningID ExclusionMatchType = "signing_id"
	// ExclusionMatchCDHash matches a code-directory hash exactly.
	ExclusionMatchCDHash ExclusionMatchType = "cdhash"
	// ExclusionMatchSHA256 matches a binary SHA-256 exactly.
	ExclusionMatchSHA256 ExclusionMatchType = "sha256"
	// ExclusionMatchCommandSubstring matches when the candidate command line contains the entry value as a substring.
	ExclusionMatchCommandSubstring ExclusionMatchType = "command_substring"
	// ExclusionMatchDomain matches a DNS name exactly or as a parent domain (entry `example.com` matches `example.com` and
	// `sub.example.com`).
	ExclusionMatchDomain ExclusionMatchType = "domain"
)

// IsValidExclusionMatchType reports whether mt is one of the defined match types. Used at the REST boundary to reject untrusted input.
func IsValidExclusionMatchType(mt ExclusionMatchType) bool {
	switch mt {
	case ExclusionMatchPathGlob, ExclusionMatchParentPathGlob, ExclusionMatchTeamID,
		ExclusionMatchSigningID, ExclusionMatchCDHash, ExclusionMatchSHA256,
		ExclusionMatchCommandSubstring, ExclusionMatchDomain:
		return true
	}
	return false
}

// MatchExclusionValue reports whether a stored exclusion of match type mt with value entry suppresses a candidate value the rule is
// about to fire on. The per-type semantics live here so the resolver and any other consumer agree on what "matches" means for each
// dimension.
func MatchExclusionValue(mt ExclusionMatchType, entry, candidate string) bool {
	switch mt {
	case ExclusionMatchPathGlob, ExclusionMatchParentPathGlob:
		// macOS /etc, /var, /tmp are symlinks into /private, and ESF reports a path in either form depending on how it was
		// resolved, so an operator who excludes `/etc/...` must still match an event reported as `/private/etc/...` (and vice
		// versa). The exclusion `entry` is a glob (`*/claude/versions/*`), which can't be canonicalized cleanly, so instead of
		// rewriting the glob we test it against BOTH macOS forms of the concrete candidate path. macOSPathAlias yields the
		// counterpart form (or "" when the path has no aliasable prefix), so a non-/private path costs one extra GlobMatch at most.
		if GlobMatch(entry, candidate) {
			return true
		}
		if alias := macOSPathAlias(candidate); alias != "" {
			return GlobMatch(entry, alias)
		}
		return false
	case ExclusionMatchCommandSubstring:
		return entry != "" && strings.Contains(candidate, entry)
	case ExclusionMatchDomain:
		// DNS names are case-insensitive and may carry a trailing dot (the FQDN root); normalize both sides so an exclusion of
		// `example.com` matches `Example.com`, `example.com.`, and `sub.example.com`.
		e := strings.TrimSuffix(strings.ToLower(entry), ".")
		c := strings.TrimSuffix(strings.ToLower(candidate), ".")
		return c == e || strings.HasSuffix(c, "."+e)
	case ExclusionMatchTeamID, ExclusionMatchSigningID, ExclusionMatchCDHash, ExclusionMatchSHA256:
		return entry == candidate
	}
	return false
}

// GlobMatch reports whether name matches pattern, where `*` matches any run of characters (including the empty run AND the path
// separator) and every other byte is a literal. A pattern with no `*` reduces to exact string equality. `*` deliberately crosses `/`
// (unlike a shell glob) so one `*/claude/versions/*` survives version churn. Standard linear-time wildcard match with single-star
// backtracking. Canonical home for the matcher the suspicious_exec allowlist introduced; the detection-config resolver reuses it for
// every path-glob exclusion.
func GlobMatch(pattern, name string) bool {
	var px, nx int
	lastStar, lastStarNx := -1, 0
	for nx < len(name) {
		switch {
		case px < len(pattern) && pattern[px] == name[nx]:
			px++
			nx++
		case px < len(pattern) && pattern[px] == '*':
			lastStar = px
			lastStarNx = nx
			px++
		case lastStar != -1:
			px = lastStar + 1
			lastStarNx++
			nx = lastStarNx
		default:
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}

// macOSPathAlias returns the counterpart macOS form of an absolute path across the /private firmlink boundary, or "" when the path
// has no aliasable prefix. /etc, /var, /tmp are symlinks into /private, so `/etc/sudoers` and `/private/etc/sudoers` name the same
// file; ESF may report either. Used by MatchExclusionValue so a path-glob exclusion matches regardless of which form the event
// carried. Only the leading segment is rewritten (a deeper `/private` is left alone), and a path under none of the three prefixes
// returns "" so the caller skips the extra match.
func macOSPathAlias(p string) string {
	// Two passes with static literals so the no-match path allocates nothing (the previous single loop computed "/private"+prefix
	// every iteration). Public -> private form first, then private -> public (slicing off the constant-length "/private" prefix).
	for _, public := range []string{"/etc", "/var", "/tmp"} {
		if p == public || strings.HasPrefix(p, public+"/") {
			return "/private" + p
		}
	}
	for _, private := range []string{"/private/etc", "/private/var", "/private/tmp"} {
		if p == private || strings.HasPrefix(p, private+"/") {
			return p[len("/private"):]
		}
	}
	return ""
}

// GlobalScope is the sentinel host-group id meaning "applies to every host" for a detection-config record whose scope is global. The
// store uses 0 for the global row so (rule_id, host_group_id) uniqueness holds and callers reason about a single int space.
const GlobalScope int64 = 0

// DetectionExclusion mirrors a row in detection_exclusions. RuleID is empty for an exclusion shared across rules. HostGroupID is
// GlobalScope for a global entry. ExpiresAt is nil for a non-expiring entry.
type DetectionExclusion struct {
	ID          int64              `db:"id" json:"id"`
	RuleID      string             `db:"rule_id" json:"rule_id"`
	MatchType   ExclusionMatchType `db:"match_type" json:"match_type"`
	Value       string             `db:"value" json:"value"`
	HostGroupID int64              `db:"host_group_id" json:"host_group_id"`
	Reason      string             `db:"reason" json:"reason"`
	Enabled     bool               `db:"enabled" json:"enabled"`
	ExpiresAt   *time.Time         `db:"expires_at" json:"expires_at,omitempty"`
	CreatedBy   string             `db:"created_by" json:"created_by"`
	// CreatedByLabel is the display label resolved from CreatedBy (the principal id) at read time: a user's email, a service account's
	// name, or "system". Not persisted (db:"-"); the operator handler fills it from the identity directory so the UI can show a name
	// instead of the raw principal id. Empty when the principal could not be resolved (e.g. deleted), in which case the UI falls back to
	// CreatedBy.
	CreatedByLabel string    `db:"-" json:"created_by_label,omitempty"`
	CreatedAt      time.Time `db:"created_at" json:"created_at"`
}

// DetectionRuleSetting mirrors a row in detection_rule_settings: the per-(rule, scope) mode + optional severity override + JSON
// settings document.
type DetectionRuleSetting struct {
	ID               int64             `db:"id" json:"id"`
	RuleID           string            `db:"rule_id" json:"rule_id"`
	HostGroupID      int64             `db:"host_group_id" json:"host_group_id"`
	Mode             DetectionRuleMode `db:"mode" json:"mode"`
	SeverityOverride string            `db:"severity_override" json:"severity_override,omitempty"`
	Settings         NullRawJSON       `db:"settings" json:"settings,omitempty"`
	UpdatedBy        string            `db:"updated_by" json:"updated_by"`
	UpdatedAt        time.Time         `db:"updated_at" json:"updated_at"`
}

// ExclusionResolver is the narrow read surface a catalog rule consults before it emits a finding. It is backed by an in-memory
// snapshot loaded from the detection-config store and swapped on reload, so Excluded is a pure in-memory lookup (no per-event DB round
// trip). A nil resolver excludes nothing, which is the correct default for an empty configuration.
type ExclusionResolver interface {
	// Excluded reports whether an enabled, unexpired exclusion of matchType whose value matches `value` applies to hostID (global
	// scope or a host group hostID belongs to).
	Excluded(ruleID string, matchType ExclusionMatchType, value, hostID string) bool
}

// RuleModeResolver is the narrow read surface the engine consults to route a finding by the resolved per-host mode and apply a
// severity override. A nil resolver behaves as "every rule alerts, no override".
type RuleModeResolver interface {
	// ResolveRuleMode returns the resolved mode and severity override for (ruleID, hostID) in a single call, most-specific-wins (a
	// host-group setting overrides global). Returning both from one resolution guarantees the engine observes a consistent
	// (mode, severity) pair even if a config reload races the call. Mode defaults to DetectionRuleModeAlert and severity to "" when
	// no setting applies.
	ResolveRuleMode(ruleID, hostID string) (mode DetectionRuleMode, severityOverride string)
}
