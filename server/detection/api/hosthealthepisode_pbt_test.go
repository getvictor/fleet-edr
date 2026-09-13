package api_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/detection/api"
)

// TestHostHealthEpisode_JSONRoundTrip pins Marshal ∘ Unmarshal == identity for a recorded sensor fault as the host page reads it
// (issue #778).
//
// Four of the fields carry `omitempty`, and two of them are where a quiet loss would do the most harm. ResolvedAtNs is a pointer
// because "still open" and "resolved at instant 0" are different answers, so a resolved episode must keep its instant even when that
// instant is zero, and an open one must stay nil rather than arriving as 0. Detail is raw JSON the console parses for the provider and
// the outcome, so its bytes must arrive as they left.
func TestHostHealthEpisode_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		want := drawHostHealthEpisode(t)

		encoded, err := json.Marshal(want)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var got api.HostHealthEpisode
		if err := json.Unmarshal(encoded, &got); err != nil {
			t.Fatalf("unmarshal %s: %v", encoded, err)
		}
		assertEpisodeEqual(t, want, got, encoded)
	})
}

// TestHostHealth_EpisodesRoundTrip covers the field that carries episodes, in the three shapes it can hold. The store always sends a
// non-nil slice so the console iterates it without a guard, and `episodes` has no omitempty, so an empty list must reach the client as
// [] rather than collapsing into null. Order is checked too: the store puts open faults first and the console renders the list as given.
func TestHostHealth_EpisodesRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var want api.HostHealth
		want.OverallStatus = rapid.SampledFrom([]string{"healthy", "degraded", "unhealthy", "unknown"}).Draw(t, "status")
		switch rapid.SampledFrom([]string{"nil", "empty", "populated"}).Draw(t, "shape") {
		case "empty":
			want.Episodes = []api.HostHealthEpisode{}
		case "populated":
			want.Episodes = rapid.SliceOfN(rapid.Custom(drawHostHealthEpisode), 1, 4).Draw(t, "episodes")
		}

		encoded, err := json.Marshal(want)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var got api.HostHealth
		if err := json.Unmarshal(encoded, &got); err != nil {
			t.Fatalf("unmarshal %s: %v", encoded, err)
		}

		if (want.Episodes == nil) != (got.Episodes == nil) {
			t.Fatalf("nil-ness of episodes must survive the wire: want nil=%t got nil=%t (wire %s)",
				want.Episodes == nil, got.Episodes == nil, encoded)
		}
		if len(got.Episodes) != len(want.Episodes) {
			t.Fatalf("length changed: want %d got %d (wire %s)", len(want.Episodes), len(got.Episodes), encoded)
		}
		for i := range want.Episodes {
			assertEpisodeEqual(t, want.Episodes[i], got.Episodes[i], encoded)
		}
	})
}

// assertEpisodeEqual compares with reflect.DeepEqual because the struct holds a pointer and a byte slice, neither of which == compares
// by value. DeepEqual also tells a nil Detail from an empty one, which is the distinction omitempty could erase.
func assertEpisodeEqual(t *rapid.T, want, got api.HostHealthEpisode, wire []byte) {
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round trip changed the value:\n want %+v (resolved %v)\n  got %+v (resolved %v)\n wire %s",
			want, want.ResolvedAtNs, got, got.ResolvedAtNs, wire)
	}
}

// drawHostHealthEpisode generates one episode. The strings include the empty string because that is the input omitempty acts on, a
// resolution instant of zero is drawn on purpose, and Detail is either absent or compact JSON, which is what the column holds: a
// JSON column hands back normalized text, and the wire carries it through unchanged.
func drawHostHealthEpisode(t *rapid.T) api.HostHealthEpisode {
	e := api.HostHealthEpisode{
		ID:          rapid.Int64().Draw(t, "id"),
		Kind:        rapid.String().Draw(t, "kind"),
		Component:   rapid.String().Draw(t, "component"),
		Subject:     rapid.String().Draw(t, "subject"),
		Severity:    rapid.SampledFrom([]string{"critical", "high", "medium", "low", ""}).Draw(t, "severity"),
		Title:       rapid.String().Draw(t, "title"),
		Description: rapid.String().Draw(t, "description"),
		OpenedAtNs:  rapid.Int64().Draw(t, "opened_at_ns"),
	}
	switch rapid.SampledFrom([]string{"open", "resolved", "resolved at zero"}).Draw(t, "resolution") {
	case "resolved":
		at := rapid.Int64().Draw(t, "resolved_at_ns")
		e.ResolvedAtNs = &at
	case "resolved at zero":
		zero := int64(0)
		e.ResolvedAtNs = &zero
	}
	if rapid.Bool().Draw(t, "has_detail") {
		detail, err := json.Marshal(map[string]any{
			"provider": rapid.String().Draw(t, "provider"),
			"outcome":  rapid.String().Draw(t, "outcome"),
			"attempts": rapid.IntRange(0, 1000).Draw(t, "attempts"),
		})
		if err != nil {
			t.Fatalf("marshal detail: %v", err)
		}
		e.Detail = detail
	}
	return e
}
