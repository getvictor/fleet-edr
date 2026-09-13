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
		// The whole value, not only the field this test is about, so a regression in a sibling field cannot pass a test that drew it.
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("round trip changed the value:\n want %+v\n  got %+v\n wire %s", want, got, encoded)
		}
	})
}

// TestHostHealthEpisode_WireShape pins the literal JSON the console reads, which a round trip cannot: renaming a field on the struct
// renames it on both sides of the trip and still passes. One open and one resolved episode cover every omitempty field in both states.
func TestHostHealthEpisode_WireShape(t *testing.T) {
	t.Parallel()
	resolvedAt := int64(0) // a resolution at instant zero must still be emitted, which is why the field is a pointer
	cases := []struct {
		name    string
		episode api.HostHealthEpisode
		want    string
	}{
		{
			name: "open, with every optional field empty",
			episode: api.HostHealthEpisode{
				ID: 7, Kind: "self_heal_failed", Component: "network_extension", Severity: "critical",
				Title: "EDR sensor could not be restored", OpenedAtNs: 1000,
			},
			want: `{"id":7,"kind":"self_heal_failed","component":"network_extension","severity":"critical",` +
				`"title":"EDR sensor could not be restored","opened_at_ns":1000}`,
		},
		{
			name: "resolved, with every optional field set",
			episode: api.HostHealthEpisode{
				ID: 8, Kind: "self_heal_failed", Component: "network_extension", Subject: "dns_proxy", Severity: "critical",
				Title: "EDR sensor could not be restored", Description: "the repair command kept failing",
				Detail:     api.NullRawJSON(`{"provider":"dns_proxy","outcome":"enable_failed","attempts":3}`),
				OpenedAtNs: 1000, ResolvedAtNs: &resolvedAt,
			},
			want: `{"id":8,"kind":"self_heal_failed","component":"network_extension","subject":"dns_proxy","severity":"critical",` +
				`"title":"EDR sensor could not be restored","description":"the repair command kept failing",` +
				`"detail":{"provider":"dns_proxy","outcome":"enable_failed","attempts":3},"opened_at_ns":1000,"resolved_at_ns":0}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := json.Marshal(tc.episode)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("wire shape changed:\n want %s\n  got %s", tc.want, got)
			}
		})
	}
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
