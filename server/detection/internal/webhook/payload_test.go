package webhook

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	detapi "github.com/fleetdm/edr/server/detection/api"
)

func TestBuild_creationEnvelope(t *testing.T) {
	t.Run("spec:alert-webhook-delivery/deliveries-carry-a-signed-versioned-payload/a-creation-event-carries-the-versioned-alert-envelope", func(t *testing.T) {
		created := time.Unix(1_767_225_600, 0).UTC()
		env := Build(BuildParams{
			EventID:        "whd_abc",
			EventType:      EventAlertCreated,
			OccurredAt:     created,
			Attempt:        1,
			ConsoleBaseURL: "https://edr.example.com/",
			Alert: detapi.Alert{
				ID: 48213, HostID: "host-1", ProcessID: 1234, RuleID: "cred_access_lsass",
				Source: detapi.AlertSourceDetection, Severity: detapi.SeverityHigh,
				Status: detapi.AlertStatusOpen, Title: "LSASS access", Description: "d",
				Techniques: detapi.JSONStringSlice{"T1003.001"}, CreatedAt: created, UpdatedAt: created,
			},
		})

		assert.Equal(t, SchemaVersion, env.SchemaVersion)
		assert.Equal(t, EventAlertCreated, env.EventType)
		assert.Equal(t, int64(48213), env.Alert.ID)
		assert.Equal(t, "open", env.Alert.Status)
		assert.Empty(t, env.Alert.PreviousStatus, "created events carry no previous status")
		assert.Equal(t, []string{"T1003.001"}, env.Alert.Techniques)
		require.NotNil(t, env.Process)
		assert.Equal(t, int64(1234), env.Process.PID)
		// Trailing slash on the base URL must not double up in the derived link.
		assert.Equal(t, "https://edr.example.com/ui/alerts?id=48213", env.Links.Console)
	})
}

func TestBuild_statusChangeCarriesPreviousStatus(t *testing.T) {
	t.Run("spec:alert-webhook-delivery/deliveries-carry-a-signed-versioned-payload/a-status-change-event-carries-the-previous-status", func(t *testing.T) {
		env := Build(BuildParams{
			EventID: "whd_def", EventType: EventAlertStatusChanged, Attempt: 1,
			PreviousStatus: "open",
			Alert:          detapi.Alert{ID: 7, HostID: "h", Status: detapi.AlertStatusResolved, Severity: detapi.SeverityLow},
		})
		assert.Equal(t, EventAlertStatusChanged, env.EventType)
		assert.Equal(t, "resolved", env.Alert.Status)
		assert.Equal(t, "open", env.Alert.PreviousStatus)
	})
}

func TestBuild_processLessOmitsProcess(t *testing.T) {
	env := Build(BuildParams{EventID: "x", EventType: EventAlertCreated, Alert: detapi.Alert{ID: 1, ProcessID: 0}})
	assert.Nil(t, env.Process, "process id 0 means a process-less alert; the process block is omitted")
}

func TestBuild_payloadNeverContainsSecret(t *testing.T) {
	t.Run("spec:alert-webhook-delivery/deliveries-carry-a-signed-versioned-payload/the-payload-never-contains-the-signing-secret", func(t *testing.T) {
		// The envelope is built purely from the alert and event metadata; there is no field through which a secret could leak.
		// This test pins that by scanning the serialized body for a sentinel that a bug wiring the secret in would surface.
		env := Build(BuildParams{EventID: "x", EventType: EventAlertCreated, Alert: detapi.Alert{ID: 1, HostID: "h"}})
		b, err := json.Marshal(env)
		require.NoError(t, err)
		assert.NotContains(t, strings.ToLower(string(b)), "secret")
	})
}

// TestBuild_roundTrip is the property-based wire-shape check: Marshal followed by Unmarshal reproduces the same document for any
// generated alert + event metadata. Times are drawn as UTC instants so RFC3339 serialization round-trips exactly.
func TestBuild_roundTrip(t *testing.T) {
	t.Run("spec:alert-webhook-delivery/deliveries-carry-a-signed-versioned-payload/the-envelope-round-trips", func(t *testing.T) {
		rapid.Check(t, func(rt *rapid.T) {
			utcTime := func(label string) time.Time {
				sec := rapid.Int64Range(0, 4_102_444_800).Draw(rt, label+"_sec")
				nsec := rapid.Int64Range(0, 999_999_999).Draw(rt, label+"_nsec")
				return time.Unix(sec, nsec).UTC()
			}
			eventType := EventAlertCreated
			if rapid.Bool().Draw(rt, "isStatusChange") {
				eventType = EventAlertStatusChanged
			}
			var resolved *time.Time
			if rapid.Bool().Draw(rt, "hasResolved") {
				r := utcTime("resolved")
				resolved = &r
			}
			env := Build(BuildParams{
				EventID:        rapid.String().Draw(rt, "eventID"),
				EventType:      eventType,
				OccurredAt:     utcTime("occurred"),
				Attempt:        rapid.IntRange(0, 10).Draw(rt, "attempt"),
				PreviousStatus: rapid.SampledFrom([]string{"", "open", "acknowledged", "resolved"}).Draw(rt, "prev"),
				ConsoleBaseURL: rapid.SampledFrom([]string{"", "https://a.example.com", "https://a.example.com/"}).Draw(rt, "base"),
				Alert: detapi.Alert{
					ID:          rapid.Int64().Draw(rt, "alertID"),
					HostID:      rapid.String().Draw(rt, "hostID"),
					ProcessID:   rapid.Int64Range(0, 1<<40).Draw(rt, "pid"),
					RuleID:      rapid.String().Draw(rt, "ruleID"),
					Source:      rapid.SampledFrom([]string{detapi.AlertSourceDetection, detapi.AlertSourceApplicationControl}).Draw(rt, "source"),
					Severity:    rapid.SampledFrom([]string{"low", "medium", "high", "critical"}).Draw(rt, "sev"),
					Title:       rapid.String().Draw(rt, "title"),
					Description: rapid.String().Draw(rt, "desc"),
					Techniques:  detapi.JSONStringSlice(rapid.SliceOf(rapid.String()).Draw(rt, "techs")),
					Status:      detapi.AlertStatus(rapid.SampledFrom([]string{"open", "acknowledged", "resolved"}).Draw(rt, "status")),
					CreatedAt:   utcTime("created"),
					UpdatedAt:   utcTime("updated"),
					ResolvedAt:  resolved,
				},
			})

			first, err := json.Marshal(env)
			require.NoError(rt, err)
			var decoded Envelope
			require.NoError(rt, json.Unmarshal(first, &decoded))
			second, err := json.Marshal(decoded)
			require.NoError(rt, err)
			assert.JSONEq(rt, string(first), string(second))
		})
	})
}
