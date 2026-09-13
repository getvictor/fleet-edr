package webhook

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	detapi "github.com/fleetdm/edr/server/detection/api"
)

// updateGolden rewrites the golden files from the current code instead of comparing against them. Run it only when an alert
// envelope's bytes are MEANT to change, which for an existing receiver is a breaking wire change and a SchemaVersion bump.
var updateGolden = flag.Bool("update", false, "rewrite golden webhook envelopes from the current code")

// goldenAlertEnvelopes are alert deliveries covering every optional part of the alert body: a process-backed creation event with
// techniques and attribution, a process-less one with none of them, and a resolved status change carrying the previous status.
func goldenAlertEnvelopes() map[string]Envelope {
	created := time.Unix(1_767_225_600, 0).UTC()
	updated := created.Add(90 * time.Second)
	resolved := updated.Add(30 * time.Second)
	return map[string]Envelope{
		"alert_created_with_process.json": Build(BuildParams{
			EventID: "11111111-1111-4111-8111-111111111111", EventType: EventAlertCreated, OccurredAt: created, Attempt: 1,
			Alert: detapi.Alert{
				ID: 42, HostID: "host-a", RuleID: "suspicious_exec", Source: "detection", Severity: "high",
				Title: "Suspicious exec chain", Description: "a shell spawned curl", Origin: "SigmaHQ, by someone",
				ProcessID: 4242, Techniques: []string{"T1059", "T1105"}, Status: "open", CreatedAt: created, UpdatedAt: created,
			},
			ConsoleBaseURL: "https://edr.example.com/",
		}),
		"alert_created_process_less.json": Build(BuildParams{
			EventID: "22222222-2222-4222-8222-222222222222", EventType: EventAlertCreated, OccurredAt: created, Attempt: 1,
			Alert: detapi.Alert{
				ID: 43, HostID: "host-b", RuleID: "privilege_launchd_plist_write", Source: "detection", Severity: "medium",
				Title: "LaunchDaemon persistence", Description: "a daemon was registered", Status: "open",
				CreatedAt: created, UpdatedAt: created,
			},
		}),
		"alert_status_changed_resolved.json": Build(BuildParams{
			EventID: "33333333-3333-4333-8333-333333333333", EventType: EventAlertStatusChanged, OccurredAt: updated, Attempt: 2,
			Alert: detapi.Alert{
				ID: 44, HostID: "host-c", RuleID: "dyld_insert", Source: "detection", Severity: "critical", Title: "DYLD injection",
				Description: "injection on exec", ProcessID: 99, Status: "resolved", CreatedAt: created, UpdatedAt: updated,
				ResolvedAt: &resolved,
			},
			PreviousStatus: "open",
			ConsoleBaseURL: "https://edr.example.com",
		}),
	}
}

// goldenHealthEnvelopes pins the health subject's bytes against drift from here on. Unlike the alert goldens there is no "before" to
// compare with, since the shape is new; what this protects is every release after it, where a receiver already parsing it would break
// on a renamed or reordered key just as an alert receiver would.
func goldenHealthEnvelopes() map[string]Envelope {
	opened := time.Unix(1_767_225_600, 0).UTC()
	return map[string]Envelope{
		"health_episode_opened.json": BuildHealthEpisode(HealthBuildParams{
			EventID: "44444444-4444-4444-8444-444444444444", Attempt: 1, HostID: "host-h",
			ConsoleBaseURL: "https://edr.example.com/",
			Episode: HealthEpisodeBody{
				ID: 3, Kind: "self_heal_failed", Component: "network_extension", Subject: "content_filter", Severity: "critical",
				Title: "EDR sensor could not be restored", Description: "automatic recovery gave up on content_filter",
				Detail:   json.RawMessage(`{"provider":"content_filter","outcome":"enable_ineffective","attempts":5}`),
				OpenedAt: opened,
			},
		}),
		"health_episode_opened_whole_component.json": BuildHealthEpisode(HealthBuildParams{
			EventID: "55555555-5555-4555-8555-555555555555", Attempt: 2, HostID: "host-i",
			Episode: HealthEpisodeBody{
				ID: 4, Kind: "self_heal_failed", Component: "endpoint_security_extension", Severity: "high",
				Title: "EDR sensor could not be restored", OpenedAt: opened,
			},
		}),
	}
}

// spec:alert-webhook-delivery/deliveries-carry-a-signed-versioned-payload/an-alert-envelope-is-unchanged-by-the-health-event-type
//
// TestAlertEnvelopesAreByteStable pins every alert envelope to the exact bytes it serialized to BEFORE host health events existed.
//
// The golden files were written from the code as it stood before the envelope learned a second subject, and are compared, not
// regenerated, by default. That ordering is the whole point: a golden produced by the same change it guards would prove only that
// the code agrees with itself. An existing receiver reads alert deliveries it has been parsing for releases, so a changed byte here
// (a key reordered, a field that used to be present going missing, an empty body appearing) is a breaking wire change even though
// the event type is unchanged, and would need a SchemaVersion bump rather than a silent release.
func TestAlertEnvelopesAreByteStable(t *testing.T) {
	t.Parallel()
	checkGolden(t, goldenAlertEnvelopes(), "an alert envelope's bytes changed, which breaks existing receivers")
}

// TestHealthEnvelopesAreByteStable pins the health subject against drift. See goldenHealthEnvelopes for why it has no "before".
func TestHealthEnvelopesAreByteStable(t *testing.T) {
	t.Parallel()
	checkGolden(t, goldenHealthEnvelopes(), "a health envelope's bytes changed, which breaks receivers already parsing it")
}

// checkGolden compares each envelope with its golden file, or rewrites the files under -update.
func checkGolden(t *testing.T, envelopes map[string]Envelope, drift string) {
	t.Helper()
	for name, env := range envelopes {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := json.MarshalIndent(env, "", "  ")
			require.NoError(t, err)
			path := filepath.Join("testdata", "golden", name)
			if *updateGolden {
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
				require.NoError(t, os.WriteFile(path, append(got, '\n'), 0o600))
				return
			}
			want, err := os.ReadFile(path) //nolint:gosec // a fixed testdata path built from a literal map key, not user input
			require.NoError(t, err, "golden missing: regenerate only if the alert wire format is meant to change")
			require.Equal(t, string(want), string(got)+"\n", drift)
		})
	}
}
