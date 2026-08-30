package catalog

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// spec:server-detection-rules-engine/registered-rule-catalog/the-engine-reports-its-rule-catalog
//
// TestAll_RegisterEveryShippedRule pins down the registration order + size of the registry, so a new rule cannot land without
// explicitly being added here. The slice this returns is the single source of truth used by the production server's main.go and the
// docs generator (tools/gen-rule-docs); a silent drift between the two would mean operators see a different surface than the ATT&CK
// coverage promises. The spec scenario "the engine reports its rule catalog" is satisfied by this test because it asserts the exact
// ID list the spec enumerates. Note the spec lists the 9 catalog rules (suspicious_exec, shell_from_office, ..., dns_c2_beacon); the
// registry also includes application_control_block which is operator-policy-driven, not part of the spec-named catalog set.
func TestAll_RegisterEveryShippedRule(t *testing.T) {
	t.Parallel()
	got := New(nil)
	wantIDs := []string{
		"suspicious_exec",
		"persistence_launchagent",
		"dyld_insert",
		"shell_from_office",
		"osascript_network_exec",
		"credential_keychain_dump",
		"privilege_launchd_plist_write",
		"sudoers_tamper",
		"application_control_block",
		"dns_c2_beacon",
		"sensor_tamper",
		"sensor_recovery_failed",
	}
	require.Len(t, got, len(wantIDs))
	for i, want := range wantIDs {
		assert.Equal(t, want, got[i].ID(), "rule at index %d", i)
	}
}

// spec:server-detection-rules-engine/platform-scoped-rule-evaluation/every-cataloged-rule-declares-at-least-one-valid-platform
//
// The api.Rule interface requires Platforms(), so a rule cannot ship without declaring its target platforms (ADR-0018). This guard
// asserts every registered rule returns a non-empty set and that every value is a recognized platform, so the engine's platform
// scoping always has a concrete, valid set to filter against. Every current rule targets darwin; a future Windows or Linux rule must
// still pass this check.
func TestAll_DeclareValidPlatforms(t *testing.T) {
	t.Parallel()
	for _, r := range New(nil) {
		platforms := r.Platforms()
		require.NotEmpty(t, platforms, "rule %s must declare at least one platform", r.ID())
		for _, p := range platforms {
			assert.Truef(t, api.IsValidPlatform(p), "rule %s declares invalid platform %q", r.ID(), p)
		}
	}
}

// TestAll_DocStructIsPopulated walks every shipped rule's Doc() and locks in the operator-facing invariants. Drives coverage of each
// rule's Doc() body from the rules package itself so SonarCloud's Go coverage profile attributes the lines correctly (cross-package
// coverage isn't aggregated under the project's current `-coverprofile` setup). Same checks as the gate in tools/gen-rule-docs,
// repeated here so a future tool can be deleted without losing the contract.
func TestAll_DocStructIsPopulated(t *testing.T) {
	t.Parallel()
	allowedSeverities := map[string]struct{}{
		api.SeverityLow:      {},
		api.SeverityMedium:   {},
		api.SeverityHigh:     {},
		api.SeverityCritical: {},
	}
	for _, r := range New(nil) {
		t.Run(r.ID(), func(t *testing.T) {
			t.Parallel()
			d := r.Doc()
			assert.NotEmpty(t, d.Title, "Title must be set for %s", r.ID())
			assert.NotEmpty(t, d.Summary, "Summary must be set for %s", r.ID())
			assert.NotEmpty(t, d.Description, "Description must be set for %s", r.ID())
			assert.Contains(t, allowedSeverities, d.Severity,
				"%s declares severity %q; expected one of the SeverityLow|Medium|High|Critical constants",
				r.ID(), d.Severity)
			assert.NotEmpty(t, d.EventTypes, "EventTypes must list at least one type for %s", r.ID())
		})
	}
}

// spec:server-detection-rules-engine/canonical-rule-naming/a-rule-names-itself-the-same-way-everywhere
//
// TestAll_CanonicalDisplayName is the structural guard against the three-names-for-one-detection drift issue #519 fixed. It pins the
// single-source-of-truth invariant for every shipped rule: Doc().Title (docs, /api/rules, UI) MUST equal DisplayName(), so the doc
// surface can never silently diverge from the canonical name again. It also enforces that the canonical name is a clean human-readable
// label, not the old "<name> (parenthetical implementation detail)" form whose detail belongs in Summary. The finding-title half of the
// invariant (Finding.Title == DisplayName) is enforced for fixture-replayed rules by server/detection/testkit Replay and by each
// rule's positive-detection test. The one rule it cannot hold for, application_control_block, is exempt because it is a
// NonDetectionProjection rather than by name: its findings carry the matched app-control rule's id and severity from the payload,
// so there is no rule-level title for them to equal. TestAll_NonDetectionClassification below pins that set, so the exemption can
// never be widened by adding a name to a list.
func TestAll_CanonicalDisplayName(t *testing.T) {
	t.Parallel()
	for _, r := range New(nil) {
		t.Run(r.ID(), func(t *testing.T) {
			t.Parallel()
			name := r.DisplayName()
			assert.NotEmpty(t, name, "DisplayName must be set for %s", r.ID())
			assert.Equal(t, name, r.Doc().Title,
				"%s: Doc().Title must equal DisplayName() so the docs and the alert name the rule one way", r.ID())
			assert.NotContains(t, name, "(",
				"%s DisplayName %q carries a parenthetical; the implementation detail belongs in Summary, the title stays a clean name",
				r.ID(), name)
			assert.Equal(t, strings.TrimSpace(name), name, "%s DisplayName must not carry leading/trailing whitespace", r.ID())
		})
	}
}

// TestAll_ThreadsExclusionResolver confirms that the four exclusion-aware rules actually thread the supplied resolver onto their
// Exclusions field. Without this, a refactor of New could silently drop the wiring and every fleet would suddenly see the alerts they
// thought they'd silenced. The other rules don't consult exclusions, so they have no Exclusions field to check.
func TestAll_ThreadsExclusionResolver(t *testing.T) {
	t.Parallel()
	res := &fakeExclusions{}
	byID := map[string]api.Rule{}
	for _, r := range New(res) {
		byID[r.ID()] = r
	}
	assert.Same(t, res, byID["suspicious_exec"].(*SuspiciousExec).Exclusions)
	assert.Same(t, res, byID["persistence_launchagent"].(*PersistenceLaunchAgent).Exclusions)
	assert.Same(t, res, byID["privilege_launchd_plist_write"].(*PrivilegeLaunchdPlistWrite).Exclusions)
	assert.Same(t, res, byID["sudoers_tamper"].(*SudoersTamper).Exclusions)
}

// Compile-time proof that the two non-detections satisfy the optional interface. A rule that stops implementing it silently
// rejoins the operator-facing catalog, which is a documentation and ATT&CK-coverage change rather than a build failure, so the
// assertion is worth stating rather than relying on the runtime test below alone.
var (
	_ api.NonDetection = (*ApplicationControlBlock)(nil)
	_ api.NonDetection = (*SensorRecoveryFailed)(nil)
)

// TestAll_NonDetectionClassification pins which registered rules are NOT detections, and why. It is the discoverable counterpart
// to the opt-in api.NonDetection interface: the declaration lives on each rule (next to the reasoning), and this test is the one
// place that shows the whole classification at a glance.
//
// It guards in both directions, which is the point. A new rule that forgets to declare itself is treated as a detection, which is
// the safe default and needs no test. The failures worth catching are the other two: a detection that accidentally opts out
// disappears from GET /api/rules, the ATT&CK coverage export and docs/detection-rules.md without any other signal; and a
// non-detection that loses its declaration silently reappears there, re-inflating the coverage figure read during procurement.
func TestAll_NonDetectionClassification(t *testing.T) {
	t.Parallel()

	wantNonDetections := map[string]api.NonDetectionKind{
		// The AUTH_EXEC walker already decided on the host; this renders that decision as an alert row.
		"application_control_block": api.NonDetectionProjection,
		// Reports our own automatic repair giving up. Both documented causes are faults in our software.
		"sensor_recovery_failed": api.NonDetectionHealth,
	}

	gotNonDetections := map[string]api.NonDetectionKind{}
	for _, r := range New(nil) {
		nd, ok := r.(api.NonDetection)
		if !ok {
			assert.True(t, api.IsDetection(r), "%s implements no NonDetection, so it must read as a detection", r.ID())
			continue
		}
		assert.False(t, api.IsDetection(r), "%s declares a non-detection kind, so it must not read as a detection", r.ID())
		gotNonDetections[r.ID()] = nd.NonDetectionKind()
	}

	assert.Equal(t, wantNonDetections, gotNonDetections,
		"the set of non-detections changed; every rule here is absent from /api/rules, /api/attack-coverage and docs/detection-rules.md")
}

// TestAll_DetectionsClaimTechniques asserts every DETECTION maps to at least one ATT&CK technique, which is what makes the
// coverage export meaningful. It is scoped to detections deliberately: application_control_block returns an empty set on purpose
// (a successful block is the absence of adversary activity, not an instance of it), and before the split that correct behaviour
// had to be special-cased out of any such check.
func TestAll_DetectionsClaimTechniques(t *testing.T) {
	t.Parallel()

	for _, r := range New(nil) {
		if !api.IsDetection(r) {
			continue
		}
		assert.NotEmpty(t, r.Techniques(), "detection %s must map to at least one ATT&CK technique", r.ID())
	}
}

// TestAll_DetectionsNameTheirAlgorithm pins that every detection declares the evaluator that decides it (issue #757).
//
// A Go-implemented rule is only inspectable if its file says which procedure runs it; without that, the exported file documents
// what the rule is for and stays silent on what it actually does. The check is scoped to detections because a non-detection is
// not exported at all, and it asserts the name is one of the registered set rather than merely non-empty: a typo would otherwise
// ship as an algorithm nothing implements, which is exactly the failure that put a fabricated `interval_regularity_and_entropy`
// into an early draft of the format.
func TestAll_DetectionsSayWhatDecidesThem(t *testing.T) {
	t.Parallel()

	// A detection says what decides it in exactly one of two ways: a graph rule names the Go evaluator that runs it, and a
	// converted rule carries a Sigma detection block in its pack file instead (issue #761). Naming both would point a reader at
	// code that no longer decides anything; naming neither leaves an exported file that cannot say what the rule does.
	known := map[string]struct{}{
		"ancestor_walk_path_prefix":              {},
		"descendant_within_window":               {},
		"dns_resolve_then_connect":               {},
		"absence_within_window":                  {},
		"exec_leading_argv_env_match":            {},
		"exec_subcommand_and_path_pattern_match": {},
		"parent_lookup_path_match":               {},
		"file_open_write_intent_match":           {},
		"btm_item_signing_verdict":               {},
	}

	seen := map[string]struct{}{}
	converted := 0
	for _, r := range New(nil) {
		if !api.IsDetection(r) {
			continue
		}
		name := api.AlgorithmNameOf(r)
		_, hasDetection := detections()[r.ID()]

		if hasDetection {
			converted++
			assert.Emptyf(t, name, "detection %s carries a detection block AND names algorithm %q; only one can decide it",
				r.ID(), name)
			continue
		}
		require.NotEmptyf(t, name,
			"detection %s names no algorithm and carries no detection block, so its exported file cannot say what decides it",
			r.ID())
		assert.Containsf(t, known, name, "detection %s names algorithm %q, which is not in the registered set", r.ID(), name)
		seen[name] = struct{}{}
	}

	assert.Positive(t, converted, "at least one rule is converted; if this drops to zero the conversion was reverted silently")
	assert.Len(t, seen, len(known),
		"every registered algorithm name must be claimed by a rule; an unclaimed name is a leftover from a deleted or renamed rule")
}
