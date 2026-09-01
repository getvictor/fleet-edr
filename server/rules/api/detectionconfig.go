package api

import (
	"context"
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
//   - alert:    the rule produces alerts as normal (what a rule operates in when it declares no default; see ModeDefaulter).
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

// ModeDefaulter is an OPTIONAL interface a registered rule implements to declare the mode it operates in when no configuration
// applies to it. A rule that does not implement it operates in alert mode, which is what every rule did before this existed.
//
// It exists because "which mode does this rule start in" is a property of the RULE, not of an operator's configuration. The
// alternative was to seed a row per rule into detection_rule_settings, which puts policy in data: every fresh install and every
// test database would have to reproduce it, a rule added later would need another migration, and an operator deleting the row
// would silently promote the rule to alerting. Declaring it in the rule keeps the default where the rule is and leaves
// detection_rule_settings meaning what it says, which is "an operator changed this".
//
// The motivating case is issue #764, which imports the upstream SigmaHQ macOS rules this project did not write. Sixty-six of the
// sixty-nine are runnable and must not alert until an operator has seen what they do; that many unfamiliar rules going straight to
// alert is how a catalog loses trust in a week. (#764 says fifty-five, written before the two enrichments it deferred shipped in
// #771 and #772; fifty-five plus those thirteen is sixty-eight field-bindable, less two whose category the agent collects too
// narrowly to ever fire. The corpus test in #763 asserts the sixty-six.)
//
// Optional and absent from Rule for the same reason NonDetection and AlgorithmNamer are: a rule with no opinion should not have to
// state one, and requiring it would make every future rule declare something the engine would read as the default anyway. (Since
// the corpus landed, the rules that DO declare a default outnumber the ones that do not; optional here is about not compelling a
// declaration, not about how many rules make one.)
//
// The -er suffix is deliberate, for the same reason AlgorithmNamer carries it: an interface named identically to its own method
// trips a lint.
type ModeDefaulter interface {
	DefaultMode() DetectionRuleMode
}

// DefaultModeOf returns r's declared default mode, or DetectionRuleModeAlert when the rule declares none.
//
// It does NOT validate the declaration. A rule declaring something that is not a mode is an author error, caught by the catalog
// guard test that asserts every registered rule's default is valid, and coercing it here would hide that in exchange for nothing:
// the guard is what keeps it out of a release.
func DefaultModeOf(r Rule) DetectionRuleMode {
	defaulter, ok := r.(ModeDefaulter)
	if !ok {
		return DetectionRuleModeAlert
	}
	return defaulter.DefaultMode()
}

// MonitorMatch is one rule's monitor-mode matches on one host, at one severity, within a single evaluated batch.
//
// Severity rides along because the counter it feeds is keyed the same way as `edr.alerts.created`, so the two series describe one
// rule identically and can be compared. That comparison is how an operator judges what promoting a rule would produce.
type MonitorMatch struct {
	RuleID   string
	HostID   string
	Severity string
	Count    int
}

// MonitorTally is what one batch's evaluation found in monitor mode, aggregated per (rule, host, severity) rather than reported
// per finding.
//
// It is RETURNED from evaluation rather than written during it, and that is the point of the type existing. A batch that fails is
// nacked and replayed whole, so anything counted while evaluating is counted again on the retry. Retries are not rare enough to
// wave away: issue #631 measured roughly 130 materialization retries a minute from a single host under a sustained condition.
// Handing the tally back lets the caller record it only once the batch is acknowledged, which counts a replayed batch once.
//
// The cost of that choice is the opposite failure: a crash between the acknowledgement and the write loses those counts, and that
// is the RISK-BEARING direction, not a safe one. A number that is too low makes a rule look quiet, which is what persuades an
// operator to promote it, and promoting a noisy rule is the alert flood issue #764 exists to prevent. It is accepted here because
// the alternative counts a replayed batch once per attempt, which is a systematic error on every retry rather than a rare one
// confined to a crash between two adjacent statements.
type MonitorTally []MonitorMatch

// Clamp returns the window that will actually be served: the default when unspecified, the cap when the request exceeds it.
//
// It lives on the type because two callers need the SAME answer for different reasons. The store needs it to build the query, and
// the handler needs it to tell the client which window the numbers cover. Clamping in only the store leaves the handler echoing
// the window that was ASKED for while serving a narrower one, which is precisely the misreport echoing the window exists to
// prevent, and it is invisible to a handler test with a fake store because the clamp never runs.
func (w MatchCountWindow) Clamp() MatchCountWindow {
	if w <= 0 {
		return DefaultMatchCountWindow
	}
	if w > MaxMatchCountWindow {
		return MaxMatchCountWindow
	}
	return w
}

// RuleMatchCount is what a rule has been doing in monitor mode over a window: how much, how widely, and how recently.
//
// Three numbers rather than one because they answer different halves of the promotion question. Matches alone cannot separate a
// rule that is noisy on one machine, which wants an exclusion, from one that is too broad everywhere, which wants leaving in
// monitor. And a rule that matched heavily last month and nothing since is a different decision again, which is what LastSeen is
// for.
// Carries `db` tags alongside `json` for the same reason DetectionRuleSetting does: the aggregate is read straight into this shape
// by the rules store and served in it, and an intermediate row struct would exist only to be copied field for field.
type RuleMatchCount struct {
	RuleID string `db:"rule_id" json:"rule_id"`
	// Matches is the total over the window. It counts MATCHES, not the alerts promotion would raise: alerts deduplicate on
	// (host, rule, subject) permanently, so a rule that keeps matching one subject counts here every time and would raise one
	// alert. Biased upward by that and downward by the recorder's documented losses, so it is an approximation.
	Matches int64 `db:"matches" json:"matches"`
	// Hosts is how many distinct hosts contributed, which is the "how widely" half.
	Hosts int64 `db:"hosts" json:"hosts"`
	// LastSeen is the most recent match in the window, or the zero time when the rule has none.
	LastSeen time.Time `db:"last_seen" json:"last_seen"`
}

// MatchCountWindow is how far back a match-count read looks, in days.
type MatchCountWindow int

const (
	// DefaultMatchCountWindow is a week: long enough that a rule firing on a weekday pattern is visible, short enough that the
	// number describes what the rule is doing now rather than what it did before the last tuning change.
	DefaultMatchCountWindow MatchCountWindow = 7
	// MaxMatchCountWindow caps the request so a reader cannot ask for a window the retention sweep has already emptied and read
	// the resulting silence as a quiet rule.
	MaxMatchCountWindow MatchCountWindow = 30
)

// MonitorMatchRecorder is the narrow write surface the detection pipeline uses to persist a batch's monitor matches once the batch
// is acknowledged. A nil recorder records nothing, which is the correct behaviour for a deployment or a test with no rules-context
// store wired: monitor mode still suppresses the alert and still emits its observability signal.
type MonitorMatchRecorder interface {
	// RecordMonitorMatches persists tally, adding to whatever is already recorded for each (rule, host, day). It is called after
	// the batch is acknowledged, so it must not be able to fail the batch: the caller logs an error and moves on.
	RecordMonitorMatches(ctx context.Context, tally MonitorTally) error
}

// RuleModeSource says where a resolved mode came from: the rule's own declaration, or a setting an operator created.
//
// It is reported alongside the mode because the two answer different questions and an operator needs both. "This rule is in monitor"
// does not say whether that is the state it shipped in or a state someone chose, and those call for opposite actions: the first is a
// rule waiting to be reviewed, the second is a decision already taken that somebody may want to revisit.
type RuleModeSource string

const (
	RuleModeSourceDefault RuleModeSource = "default"
	RuleModeSourceSetting RuleModeSource = "setting"
)

// GlobalRuleMode is a rule's mode at global scope together with where that mode came from.
type GlobalRuleMode struct {
	Mode   DetectionRuleMode
	Source RuleModeSource
}

// GlobalRuleModeResolver is the narrow read surface the catalog listing consults to report the mode a rule actually runs in, rather
// than only the mode it declares. It exists because the spec requires a rule whose global mode is `disabled` to stay listed by
// GET /api/rules "with its mode indicated", and DefaultMode is the rule's own declaration, which a setting overrides.
//
// Global scope is the whole question here, and it is what a catalog listing can answer: the listing names no host, so a per-host
// mode is a question it cannot ask. An implementation MUST resolve it by selecting globally scoped settings directly, NOT by asking
// a per-host resolver about an empty host id. That shortcut reads as equivalent, since no host belongs to a group, but it routes
// the answer through whatever decides group membership, which is free to admit a host id it has never seen: a permissive one would
// let a group-scoped setting decide a question that is supposed to be global.
//
// Separate from RuleModeResolver rather than a third return value on it. The mode and its source must come from ONE resolution for
// the same reason ResolveRuleMode returns the mode and the severity override together: two calls can straddle a config reload and
// report a mode from one snapshot with a source from another, which is a listing that contradicts itself. Widening the engine's
// interface to carry a field the engine does not read would put that cost on the hot path to serve a listing.
type GlobalRuleModeResolver interface {
	// GlobalRuleMode returns the globally resolved mode for ruleID and whether a setting or the rule's own default produced it.
	//
	// ruleDefault is the mode to apply when no setting applies, taken from the rule itself (DefaultModeOf), for the same reason
	// ResolveRuleMode takes it: the fallback lives in one place and a caller cannot forget to apply it.
	GlobalRuleMode(ruleID string, ruleDefault DetectionRuleMode) GlobalRuleMode
}

// GlobalRuleModeOf resolves ruleID's global mode through r, or reports the rule's own default when there is no resolver.
//
// A nil resolver is the docs-generator path, which renders rule documentation with no database behind it. Reporting the declared
// default there is right rather than merely safe: with no configuration to read, the rule's own declaration IS the mode it runs in.
func GlobalRuleModeOf(r GlobalRuleModeResolver, ruleID string, ruleDefault DetectionRuleMode) GlobalRuleMode {
	if r == nil {
		return GlobalRuleMode{Mode: ruleDefault, Source: RuleModeSourceDefault}
	}
	return r.GlobalRuleMode(ruleID, ruleDefault)
}

// RuleModeResolver is the narrow read surface the engine consults to route a finding by the resolved per-host mode and apply a
// severity override. A nil resolver leaves every rule at its own declared default (see ModeDefaulter) with no override, which is
// "every rule alerts" for a rule that declares nothing and therefore was the whole story before defaults existed.
type RuleModeResolver interface {
	// ResolveRuleMode returns the resolved mode and severity override for (ruleID, hostID) in a single call, most-specific-wins (a
	// host-group setting overrides global). Returning both from one resolution guarantees the engine observes a consistent
	// (mode, severity) pair even if a config reload races the call.
	//
	// ruleDefault is the mode to apply when no setting applies, which the caller takes from the rule itself (DefaultModeOf).
	// Passing it in rather than returning "no setting applies" keeps the fallback in one place: a caller cannot forget to apply it,
	// and the notion of an unconfigured rule never leaves this interface. Severity is "" whenever the default is used, since a
	// severity override is something only a setting can carry.
	ResolveRuleMode(ruleID, hostID string, ruleDefault DetectionRuleMode) (mode DetectionRuleMode, severityOverride string)
}
