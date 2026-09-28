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

// spec:endpoint-event-collection/launch-item-registration-event-capture/a-login-item-is-registered-through-smappservice
// spec:endpoint-event-collection/launch-item-registration-event-capture/an-app-is-added-to-the-user-s-login-items
//
// TestBtmExecutableSigning_LoginItems covers the shape a login item takes, captured on a VM (issue #1167): SMAppService names the
// item relative to the registering app's bundle and reports no executable_path, so the item path is resolved against app_url and
// the helper bundle it names is what is signed.
func TestBtmExecutableSigning_LoginItems(t *testing.T) {
	t.Parallel()
	const app = `"app_url":"file:///Users/victor/Applications/EdrLoginTest.app/"`
	cases := []struct {
		name string
		in   string
		// wantItem is the item_path the output carries.
		wantItem string
		// wantSigned is the path the evaluator is asked about, or "" when it must not be asked.
		wantSigned string
	}{
		{
			name:       "a login item is resolved against its app and its bundle signed",
			in:         `{"item_type":"login_item","item_path":"Contents/Library/LoginItems/EdrLoginTestHelper.app",` + app + `}`,
			wantItem:   "file:///Users/victor/Applications/EdrLoginTest.app/Contents/Library/LoginItems/EdrLoginTestHelper.app",
			wantSigned: "/Users/victor/Applications/EdrLoginTest.app/Contents/Library/LoginItems/EdrLoginTestHelper.app",
		},
		{
			name: "an escaped space is a space in the path signed",
			in: `{"item_type":"login_item","item_path":"Contents/Library/LoginItems/My%20Helper.app",` +
				`"app_url":"file:///Applications/My%20App.app/"}`,
			wantItem:   "file:///Applications/My%20App.app/Contents/Library/LoginItems/My%20Helper.app",
			wantSigned: "/Applications/My App.app/Contents/Library/LoginItems/My Helper.app",
		},
		{
			name: "an app without its trailing slash is still descended into",
			in: `{"item_type":"login_item","item_path":"Contents/Library/LoginItems/EdrLoginTestHelper.app",` +
				`"app_url":"file:///Applications/My%20App.app"}`,
			wantItem:   "file:///Applications/My%20App.app/Contents/Library/LoginItems/EdrLoginTestHelper.app",
			wantSigned: "/Applications/My App.app/Contents/Library/LoginItems/EdrLoginTestHelper.app",
		},
		{
			name:     "a login item with no app to resolve against is left as reported, and not signed",
			in:       `{"item_type":"login_item","item_path":"Contents/Library/LoginItems/EdrLoginTestHelper.app"}`,
			wantItem: "Contents/Library/LoginItems/EdrLoginTestHelper.app",
		},
		{
			name:       "an absolute item keeps its path, and a login item's bundle is signed",
			in:         `{"item_type":"login_item","item_path":"file:///Applications/Helper.app",` + app + `}`,
			wantItem:   "file:///Applications/Helper.app",
			wantSigned: "/Applications/Helper.app",
		},
		{
			name: "another item type is resolved, and signed by its executable_path",
			in: `{"item_type":"agent","item_path":"Contents/Library/LaunchAgents/com.example.plist",` + app +
				`,"executable_path":"/Users/victor/Applications/EdrLoginTest.app/Contents/MacOS/agent"}`,
			wantItem:   "file:///Users/victor/Applications/EdrLoginTest.app/Contents/Library/LaunchAgents/com.example.plist",
			wantSigned: "/Users/victor/Applications/EdrLoginTest.app/Contents/MacOS/agent",
		},
		{
			name:       "an app added to the login items is signed as its bundle",
			in:         `{"item_type":"app","item_path":"file:///Users/victor/Applications/EdrLegacyTest.app/"}`,
			wantItem:   "file:///Users/victor/Applications/EdrLegacyTest.app/",
			wantSigned: "/Users/victor/Applications/EdrLegacyTest.app/",
		},
		{
			name:     "another item type with no executable_path is not signed by its item",
			in:       `{"item_type":"agent","item_path":"Contents/Library/LaunchAgents/com.example.plist",` + app + `}`,
			wantItem: "file:///Users/victor/Applications/EdrLoginTest.app/Contents/Library/LaunchAgents/com.example.plist",
		},
		{
			name: "a signature already present is kept, and the item still resolved",
			in: `{"item_type":"login_item","item_path":"Contents/Library/LoginItems/EdrLoginTestHelper.app",` + app +
				`,"executable_code_signing":{"team_id":"KEEPME0000","signing_id":"x","flags":0,"is_platform_binary":false}}`,
			wantItem: "file:///Users/victor/Applications/EdrLoginTest.app/Contents/Library/LoginItems/EdrLoginTestHelper.app",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var asked []string
			eval := func(path string) (*codesign.Result, bool) {
				asked = append(asked, path)
				return &codesign.Result{TeamID: "ABCDE12345"}, true
			}
			got := BtmExecutableSigning([]byte(`{"event_type":"btm_launch_item_add","payload":`+tc.in+`}`), eval)

			var env struct {
				Payload struct {
					ItemPath string          `json:"item_path"`
					Signing  json.RawMessage `json:"executable_code_signing"`
				} `json:"payload"`
			}
			if err := json.Unmarshal(got, &env); err != nil {
				t.Fatalf("output is not valid JSON: %v (%s)", err, got)
			}
			if env.Payload.ItemPath != tc.wantItem {
				t.Errorf("item_path\n got: %s\nwant: %s", env.Payload.ItemPath, tc.wantItem)
			}
			switch {
			case tc.wantSigned == "" && len(asked) != 0:
				t.Errorf("the evaluator was asked about %q and should not have been", asked)
			case tc.wantSigned != "" && (len(asked) != 1 || asked[0] != tc.wantSigned):
				t.Errorf("the evaluator was asked about %q, want [%s]", asked, tc.wantSigned)
			case tc.wantSigned != "" && len(env.Payload.Signing) == 0:
				t.Errorf("executable_code_signing was not filled")
			}
		})
	}
}
