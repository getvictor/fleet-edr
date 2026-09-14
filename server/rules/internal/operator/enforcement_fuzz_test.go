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
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		var req updateRuleRequest
		if err := json.Unmarshal([]byte(body), &req); err != nil {
			return
		}
		var members map[string]json.RawMessage
		if err := json.Unmarshal([]byte(body), &members); err != nil {
			return
		}
		// encoding/json matches member names case-insensitively, so "Enforcement" names the field as much as "enforcement" does.
		var spellings []string
		for key := range members {
			if strings.EqualFold(key, "enforcement") {
				spellings = append(spellings, key)
			}
		}
		named := len(spellings) > 0
		got := req.Enforcement.value()
		if named && got == nil {
			t.Fatalf("%s names enforcement but decoded as absent", body)
		}
		if !named && got != nil {
			t.Fatalf("%s omits enforcement but decoded as %q", body, *got)
		}
		// With one spelling the decoded member is that member's last occurrence, which is what the map kept.
		if len(spellings) == 1 && string(members[spellings[0]]) == "null" && *got != api.Enforcement("") {
			t.Fatalf("%s ends with a null enforcement but decoded as %q", body, *got)
		}
	})
}
