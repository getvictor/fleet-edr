package api_test

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/detection/api"
)

// TestAlert_JSONRoundTrip pins Marshal ∘ Unmarshal == identity for the alert wire shape, which gained a disposition with monitor records
// (issue #994). The console decides what a row is from that field, including whether to offer triage on it, so a disposition that did not
// survive the wire would present a monitor record as an alert.
//
// Subject is the one field excluded, and deliberately: it is the internal dedup identity and is tagged out of the JSON, so it is drawn
// empty. Timestamps are drawn in UTC at microsecond precision, which is what the TIMESTAMP(6) columns hold.
func TestAlert_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		want := drawAlert(t)

		encoded, err := json.Marshal(want)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var got api.Alert
		if err := json.Unmarshal(encoded, &got); err != nil {
			t.Fatalf("unmarshal %s: %v", encoded, err)
		}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("round trip changed the value:\n want %+v\n  got %+v\n wire %s", want, got, encoded)
		}
	})
}

func drawTime(t *rapid.T, label string) time.Time {
	return time.UnixMicro(rapid.Int64Range(0, 4_102_444_800_000_000).Draw(t, label)).UTC()
}

func drawAlert(t *rapid.T) api.Alert {
	a := api.Alert{
		ID:     rapid.Int64().Draw(t, "id"),
		HostID: rapid.String().Draw(t, "host_id"),
		RuleID: rapid.String().Draw(t, "rule_id"),
		Source: rapid.SampledFrom([]string{api.AlertSourceDetection, api.AlertSourceApplicationControl}).Draw(t, "source"),
		Disposition: rapid.SampledFrom([]api.AlertDisposition{
			api.AlertDispositionAlert, api.AlertDispositionMonitor,
		}).Draw(t, "disposition"),
		Severity:    rapid.SampledFrom([]string{"low", "medium", "high", "critical"}).Draw(t, "severity"),
		Title:       rapid.String().Draw(t, "title"),
		Description: rapid.String().Draw(t, "description"),
		Origin:      rapid.String().Draw(t, "origin"),
		ProcessID:   rapid.Int64().Draw(t, "process_id"),
		Status: rapid.SampledFrom([]api.AlertStatus{
			api.AlertStatusOpen, api.AlertStatusAcknowledged, api.AlertStatusResolved,
		}).Draw(t, "status"),
		CreatedAt: drawTime(t, "created_at"),
		UpdatedAt: drawTime(t, "updated_at"),
	}
	// techniques carries omitempty, so an empty list is absent on the wire and comes back nil: drawn nil or non-empty.
	if rapid.Bool().Draw(t, "has_techniques") {
		a.Techniques = rapid.SliceOfN(rapid.String(), 1, 4).Draw(t, "techniques")
	}
	if rapid.Bool().Draw(t, "resolved") {
		at := drawTime(t, "resolved_at")
		a.ResolvedAt = &at
	}
	if rapid.Bool().Draw(t, "has_updated_by") {
		by := rapid.String().Draw(t, "updated_by")
		a.UpdatedBy = &by
	}
	return a
}
