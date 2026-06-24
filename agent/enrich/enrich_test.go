package enrich

import (
	"encoding/json"
	"testing"

	"github.com/fleetdm/edr/agent/codesign"
)

// fakeEval returns a fixed result for any non-empty path unless configured to
// fail, so the table tests exercise BtmExecutableSigning without darwin/cgo.
func fakeEval(result *codesign.Result, ok bool) Evaluator {
	return func(_ string) (*codesign.Result, bool) { return result, ok }
}

// btmSigningCase is one TestBtmExecutableSigning table row, named so runBtmSigningCase can carry the per-case assertion
// logic out of the test body (keeping TestBtmExecutableSigning's cognitive complexity in bounds).
type btmSigningCase struct {
	name string
	in   string
	eval Evaluator
	// wantSigning is the executable_code_signing object expected in the output, or "" to assert the field is absent.
	wantSigning string
	// wantUnchanged asserts the bytes are returned verbatim (no re-marshal).
	wantUnchanged bool
}

func TestBtmExecutableSigning(t *testing.T) {
	t.Parallel()
	signed := &codesign.Result{TeamID: "ABCDE12345", SigningID: "com.evil.dropper", IsPlatformBinary: false}

	tests := []btmSigningCase{
		{
			name:        "fills missing signing from a readable executable",
			in:          `{"event_type":"btm_launch_item_add","payload":{"item_type":"daemon","executable_path":"/tmp/d"}}`,
			eval:        fakeEval(signed, true),
			wantSigning: `{"team_id":"ABCDE12345","signing_id":"com.evil.dropper","flags":0,"is_platform_binary":false}`,
		},
		{
			name:        "fills explicit-null signing",
			in:          `{"event_type":"btm_launch_item_add","payload":{"executable_path":"/tmp/d","executable_code_signing":null}}`,
			eval:        fakeEval(signed, true),
			wantSigning: `{"team_id":"ABCDE12345","signing_id":"com.evil.dropper","flags":0,"is_platform_binary":false}`,
		},
		{
			name:          "leaves already-present signing untouched",
			in:            `{"event_type":"btm_launch_item_add","payload":{"executable_path":"/tmp/d","executable_code_signing":{"team_id":"KEEPME0000","signing_id":"x","flags":0,"is_platform_binary":true}}}`,
			eval:          fakeEval(signed, true),
			wantUnchanged: true,
		},
		{
			name:          "non-btm event passes through",
			in:            `{"event_type":"exec","payload":{"path":"/bin/ls"}}`,
			eval:          fakeEval(signed, true),
			wantUnchanged: true,
		},
		{
			name:          "missing executable_path passes through",
			in:            `{"event_type":"btm_launch_item_add","payload":{"item_type":"daemon"}}`,
			eval:          fakeEval(signed, true),
			wantUnchanged: true,
		},
		{
			name:          "empty executable_path passes through",
			in:            `{"event_type":"btm_launch_item_add","payload":{"executable_path":""}}`,
			eval:          fakeEval(signed, true),
			wantUnchanged: true,
		},
		{
			name:          "unreadable executable leaves field unset",
			in:            `{"event_type":"btm_launch_item_add","payload":{"executable_path":"/tmp/gone"}}`,
			eval:          fakeEval(nil, false),
			wantUnchanged: true,
		},
		{
			name:          "missing payload passes through",
			in:            `{"event_type":"btm_launch_item_add"}`,
			eval:          fakeEval(signed, true),
			wantUnchanged: true,
		},
		{
			name:          "malformed json passes through",
			in:            `{not json`,
			eval:          fakeEval(signed, true),
			wantUnchanged: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runBtmSigningCase(t, tc)
		})
	}
}

// runBtmSigningCase exercises BtmExecutableSigning for one table row and asserts either the verbatim-passthrough property
// (wantUnchanged) or that the enriched output carries the expected executable_code_signing object.
func runBtmSigningCase(t *testing.T, tc btmSigningCase) {
	t.Helper()
	got := BtmExecutableSigning([]byte(tc.in), tc.eval)

	if tc.wantUnchanged {
		if string(got) != tc.in {
			t.Fatalf("expected unchanged bytes\n got: %s\nwant: %s", got, tc.in)
		}
		return
	}

	var env struct {
		EventType string          `json:"event_type"`
		Payload   json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(got, &env); err != nil {
		t.Fatalf("output is not valid JSON: %v (%s)", err, got)
	}
	var payload struct {
		Signing json.RawMessage `json:"executable_code_signing"`
	}
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		t.Fatalf("output payload is not valid JSON: %v", err)
	}
	if string(payload.Signing) != tc.wantSigning {
		t.Errorf("executable_code_signing\n got: %s\nwant: %s", payload.Signing, tc.wantSigning)
	}
}

// TestBtmExecutableSigningPreservesUnknownFields guards the round-trip: every
// envelope and payload key the agent does not model must survive enrichment.
func TestBtmExecutableSigningPreservesUnknownFields(t *testing.T) {
	t.Parallel()
	in := `{"event_type":"btm_launch_item_add","host_id":"H1","timestamp_ns":42,` +
		`"payload":{"item_type":"daemon","item_path":"/Library/LaunchDaemons/x.plist","executable_path":"/tmp/d",` +
		`"managed":false,"instigator_pid":99,"future_field":{"nested":true}}}`

	got := BtmExecutableSigning([]byte(in), fakeEval(&codesign.Result{TeamID: "T"}, true))

	var out map[string]json.RawMessage
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, k := range []string{"event_type", "host_id", "timestamp_ns", "payload"} {
		if _, ok := out[k]; !ok {
			t.Errorf("envelope lost key %q", k)
		}
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(out["payload"], &payload); err != nil {
		t.Fatalf("invalid payload JSON: %v", err)
	}
	for _, k := range []string{"item_type", "item_path", "executable_path", "managed", "instigator_pid", "future_field", "executable_code_signing"} {
		if _, ok := payload[k]; !ok {
			t.Errorf("payload lost key %q", k)
		}
	}
	if string(payload["future_field"]) != `{"nested":true}` {
		t.Errorf("future_field corrupted: %s", payload["future_field"])
	}
}
