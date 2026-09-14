package operator

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/fleetdm/edr/server/rules/api"
)

// FuzzUpdateRuleRequestEnforcement decodes arbitrary PATCH bodies and holds the one property the enforcement field exists for: a body
// that names the field is never read as leaving it unchanged. The value may be anything, and the store's validation decides whether
// it is acceptable, but a decoded request that carried the member must hand the store a non-nil enforcement, and one that did not
// must hand it nil.
func FuzzUpdateRuleRequestEnforcement(f *testing.F) {
	for _, seed := range []string{
		`{"reason":"r"}`, `{"enforcement":"DETECT","reason":"r"}`, `{"enforcement":null}`, `{"enforcement":"DETECT","enforcement":null}`,
		`{"enforcement":1}`, `{"enforcement":""}`, `{"enforcement":["PROTECT"]}`, `null`, `{}`,
		`{"enforcement":"DETECT","Enforcement":null}`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		var req updateRuleRequest
		if err := json.Unmarshal([]byte(body), &req); err != nil {
			return
		}
		// The member encoding/json applies is the LAST one whose name matches case-insensitively, so walk the object in order.
		named, last, ok := lastEnforcementMember(body)
		if !ok {
			return
		}
		got := req.Enforcement.value()
		if named && got == nil {
			t.Fatalf("%s names enforcement but decoded as absent", body)
		}
		if !named && got != nil {
			t.Fatalf("%s omits enforcement but decoded as %q", body, *got)
		}
		if named && string(last) == "null" && *got != api.Enforcement("") {
			t.Fatalf("%s ends with a null enforcement but decoded as %q", body, *got)
		}
	})
}

// lastEnforcementMember walks a top-level JSON object in order and reports whether any member's name matches "enforcement"
// case-insensitively, and the raw value of the last such member. ok is false when body is not an object.
func lastEnforcementMember(body string) (named bool, last json.RawMessage, ok bool) {
	dec := json.NewDecoder(strings.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return false, nil, false
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return false, nil, false
		}
		key, _ := tok.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return false, nil, false
		}
		if strings.EqualFold(key, "enforcement") {
			named, last = true, value
		}
	}
	return named, last, true
}
