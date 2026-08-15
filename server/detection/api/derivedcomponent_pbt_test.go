package api_test

import (
	"encoding/json"
	"testing"

	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/detection/api"
)

// TestDerivedComponent_JSONRoundTrip pins Marshal ∘ Unmarshal == identity for the derived health condition (issue #677).
//
// This is the repo's standing rule for a new wire-format struct, and it earns its place here for a specific reason: two of the five
// fields carry `omitempty`, and the console reads Reason and Message to tell an operator which provider to act on. A field that
// silently failed to survive the wire would not break any handler, it would just quietly empty the part of the response a human
// reads.
//
// Property-based rather than table-driven because the interesting inputs are the ones nobody thinks to write down: empty strings
// beside populated ones, a zero LastTransitionNs (which every derived condition actually carries), and negative or extreme
// timestamps.
func TestDerivedComponent_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		want := drawDerivedComponent(t)

		encoded, err := json.Marshal(want)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var got api.DerivedComponent
		if err := json.Unmarshal(encoded, &got); err != nil {
			t.Fatalf("unmarshal %s: %v", encoded, err)
		}
		if got != want {
			t.Fatalf("round trip changed the value:\n want %+v\n  got %+v\n wire %s", want, got, encoded)
		}
	})
}

// TestHostHealth_DerivedComponentsRoundTrip covers the field in the response that carries them, where the shapes that matter are the
// three the server actually produces: a populated list (whose ORDER is meaningful, since the console renders it as given), an empty
// list, and nil, which is the normal case for a healthy host.
//
// nil and empty are checked to survive as themselves rather than collapsing into one another: `derived_components` has no omitempty,
// so nil must reach the client as JSON null and empty as [], and a client distinguishing "nothing derived" from "not evaluated"
// depends on that staying true.
func TestHostHealth_DerivedComponentsRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var want api.HostHealth
		want.OverallStatus = rapid.SampledFrom([]string{"healthy", "degraded", "unhealthy", "unknown"}).Draw(t, "status")
		want.ReportedAtNs = rapid.Int64().Draw(t, "reported_at_ns")
		switch rapid.SampledFrom([]string{"nil", "empty", "populated"}).Draw(t, "shape") {
		case "empty":
			want.DerivedComponents = []api.DerivedComponent{}
		case "populated":
			want.DerivedComponents = rapid.SliceOfN(rapid.Custom(drawDerivedComponent), 1, 4).Draw(t, "derived")
		}

		encoded, err := json.Marshal(want)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var got api.HostHealth
		if err := json.Unmarshal(encoded, &got); err != nil {
			t.Fatalf("unmarshal %s: %v", encoded, err)
		}

		if got.OverallStatus != want.OverallStatus || got.ReportedAtNs != want.ReportedAtNs {
			t.Fatalf("scalar fields changed:\n want %+v\n  got %+v", want, got)
		}
		if (want.DerivedComponents == nil) != (got.DerivedComponents == nil) {
			t.Fatalf("nil-ness of derived_components must survive the wire: want nil=%t got nil=%t (wire %s)",
				want.DerivedComponents == nil, got.DerivedComponents == nil, encoded)
		}
		if len(got.DerivedComponents) != len(want.DerivedComponents) {
			t.Fatalf("length changed: want %d got %d (wire %s)", len(want.DerivedComponents), len(got.DerivedComponents), encoded)
		}
		for i := range want.DerivedComponents {
			if got.DerivedComponents[i] != want.DerivedComponents[i] {
				t.Fatalf("element %d changed (order or content):\n want %+v\n  got %+v", i,
					want.DerivedComponents[i], got.DerivedComponents[i])
			}
		}
	})
}

// drawDerivedComponent generates one condition. The string generators deliberately include the empty string, because Reason and
// Message are the two fields carrying omitempty and empty is exactly the input that exercises it.
func drawDerivedComponent(t *rapid.T) api.DerivedComponent {
	return api.DerivedComponent{
		Type:             rapid.String().Draw(t, "type"),
		Status:           rapid.SampledFrom([]string{"healthy", "degraded", "unhealthy", "unknown", ""}).Draw(t, "status"),
		Reason:           rapid.String().Draw(t, "reason"),
		Message:          rapid.String().Draw(t, "message"),
		LastTransitionNs: rapid.Int64().Draw(t, "last_transition_ns"),
	}
}
