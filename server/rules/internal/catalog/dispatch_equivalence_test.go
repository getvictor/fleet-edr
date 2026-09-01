package catalog

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
)

// loadFixtureEvents decodes one replay fixture's event batch.
func loadFixtureEvents(t *testing.T, path string) []detectionapi.Event {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // fixture path from a fixed glob, not user input
	require.NoError(t, err)
	var fixture struct {
		Events []detectionapi.Event `json:"events"`
	}
	require.NoError(t, json.Unmarshal(raw, &fixture), "decode %s", path)
	require.NotEmpty(t, fixture.Events, "%s carries no events", path)
	return fixture.Events
}

// distinctEventTypes returns the event types a batch carries, which is what the engine dispatches on.
func distinctEventTypes(events []detectionapi.Event) []string {
	present := make([]string, 0, 4)
	for _, ev := range events {
		if !slices.Contains(present, ev.EventType) {
			present = append(present, ev.EventType)
		}
	}
	return present
}

// wouldDispatch mirrors the engine's decision: a rule is offered a batch when the batch carries a type it declares.
func wouldDispatch(declared, present []string) bool {
	for _, et := range declared {
		if slices.Contains(present, et) {
			return true
		}
	}
	return false
}

// spec:server-detection-rules-engine/a-rule-declares-the-event-types-it-consumes/a-rule-finds-nothing-in-a-batch-of-types-it-does-not-declare
//
// TestAll_ARuleThatFindsSomethingDeclaredTheBatchesEventType is the corpus equivalence gate for engine dispatch (issue #762).
//
// The engine invokes a rule only when the batch carries an event type it declares. Dispatch is therefore behaviour-preserving
// exactly when no rule can find something in a batch carrying none of its declared types, which is what this asserts over the real
// fixture corpus:
//
//	a rule produced findings from this batch  =>  the batch carried a type that rule declares
//
// Stated that way it needs no second engine run to compare against. Running the corpus twice, once dispatched and once not, would
// answer the same question less directly, since the only thing dispatch can change is whether a rule is invoked at all.
//
// This is the gate the issue asks for, and it is stronger than the synthetic tripwire in registry_test.go because the batches are
// real recorded telemetry with payloads that genuinely fire these rules, rather than payloads assembled to look incriminating.
func TestAll_ARuleThatFindsSomethingDeclaredTheBatchesEventType(t *testing.T) {
	t.Parallel()

	fixtures, err := filepath.Glob(filepath.Join("fixtures", "*", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, fixtures, "no fixtures found, so this gate would prove nothing")

	rules := New(nil)
	require.NotEmpty(t, rules)

	// The gate is only as good as the rules the corpus actually fires, so the covered set is asserted EXACTLY rather than as "at
	// least one". "At least one" would stay green while some other rule's declaration silently went wrong, and it would hide the
	// fact that part of the catalog is untested here.
	//
	// All twelve authored rules now carry replay fixtures (issue #773), so every one of them appears below. Once the imported
	// corpus has its smoke fixtures too, this list becomes exactly the catalog and should be DERIVED from New() rather than
	// written out; it stays literal only while pendingFixtures is non-empty and some rules therefore cannot fire here.
	//
	// proc_creation_macos_base64_decode has a fixture of its own: it is the worked example the imported corpus's generated smoke
	// fixtures will follow. The other four proc_creation_macos_* entries have no fixture and fire as OVERLAPS on the authored
	// ones: the keychain-dump capture trips the imported credential rule, the Office fixture trips the imported office-child
	// rule, the launchctl fixture trips the imported launchctl rule. Those four are worth having rather than suppressing. They
	// are direct evidence that the vendored corpus matches the same telemetry the hand-written rules do, and because the vendored
	// rules ship in monitor mode the overlap is exactly the recorded signal an operator compares against the alert before
	// deciding whether promoting one would add anything.
	coveredByCorpus := []string{
		"application_control_block",
		"credential_keychain_dump",
		"dns_c2_beacon",
		"dyld_insert",
		"osascript_network_exec",
		"persistence_launchagent",
		"privilege_launchd_plist_write",
		"proc_creation_macos_applescript",
		"proc_creation_macos_base64_decode",
		"proc_creation_macos_creds_from_keychain",
		"proc_creation_macos_launchctl_execution",
		"proc_creation_macos_office_susp_child_processes",
		"sensor_recovery_failed",
		"sensor_tamper",
		"shell_from_office",
		"sudoers_tamper",
		"suspicious_exec",
	}
	var mu sync.Mutex
	fired := map[string]int{}
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		got := slices.Sorted(maps.Keys(fired))
		assert.Equal(t, coveredByCorpus, got,
			"the set of rules this corpus exercises changed; if a fixture corpus was added, extend coveredByCorpus, and if one "+
				"stopped firing that is a regression in the rule, not in this list")
	})

	for _, path := range fixtures {
		t.Run(filepath.ToSlash(path), func(t *testing.T) {
			t.Parallel()

			events := loadFixtureEvents(t, path)
			present := distinctEventTypes(events)

			ctx := t.Context()
			s := openCatalogStore(t)
			require.NoError(t, s.InsertEvents(ctx, events))
			require.NoError(t, s.ProcessBatch(ctx, events))

			for _, r := range rules {
				// The error is ignored deliberately: the engine already logs and swallows a rule-evaluation error, and a
				// finding is the only thing dispatch could drop.
				findings, _ := r.Evaluate(ctx, events, s.GraphReader())
				if len(findings) == 0 {
					continue
				}
				declared := r.Doc().EventTypes
				mu.Lock()
				fired[r.ID()] += len(findings)
				mu.Unlock()

				assert.True(t, wouldDispatch(declared, present),
					"rule %q produced %d finding(s) from a batch carrying %v, but declares only %v, so dispatch would have "+
						"skipped it and lost those findings", r.ID(), len(findings), present, declared)
			}
		})
	}
}
