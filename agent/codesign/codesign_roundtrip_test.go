package codesign

import (
	"encoding/json"
	"testing"

	"pgregory.net/rapid"
)

// TestResultJSONRoundTrip is the wire-format round-trip property for Result: for any field values, Unmarshal . Marshal is
// the identity. Result is the on-the-wire `code_signing` shape (schema/events.json) the agent emits into a
// btm_launch_item_add payload, so it carries the same PBT round-trip guarantee as the other wire structs (CLAUDE.md).
func TestResultJSONRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		in := Result{
			TeamID:           rapid.String().Draw(t, "team_id"),
			SigningID:        rapid.String().Draw(t, "signing_id"),
			Flags:            rapid.Int().Draw(t, "flags"),
			IsPlatformBinary: rapid.Bool().Draw(t, "is_platform_binary"),
		}
		encoded, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var out Result
		if err := json.Unmarshal(encoded, &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if out != in {
			t.Fatalf("round-trip mismatch: in=%+v out=%+v json=%s", in, out, encoded)
		}
	})
}
