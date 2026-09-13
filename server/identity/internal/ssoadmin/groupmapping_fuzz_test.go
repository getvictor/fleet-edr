package ssoadmin

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/fleetdm/edr/server/identity/internal/rbac"
	"github.com/fleetdm/edr/server/identity/internal/ssoconfig"
)

// FuzzValidGroupMapping feeds the group mapping validation the claim and two mappings exactly as decoded from a request body. It must
// not panic, and whatever it accepts must be what it promises: a trimmed claim within the column bound, present exactly when there are
// mappings, and mappings in order with trimmed, non-empty, distinct groups within the bound and grantable, lower-cased roles.
func FuzzValidGroupMapping(f *testing.F) {
	f.Add("groups", "edr-admins", "admin", "edr-auditors", "Auditor")
	f.Add(" groups ", " edr-admins", "ADMIN", "edr-admins ", "auditor")
	f.Add("", "edr-admins", "super_admin", "", "")
	f.Add("groups", "日本", "senior_analyst", "\x00", "analyst")
	f.Fuzz(func(t *testing.T, claim, firstGroup, firstRole, secondGroup, secondRole string) {
		in := []ssoconfig.GroupRole{{Group: firstGroup, Role: firstRole}, {Group: secondGroup, Role: secondRole}}
		for _, mappings := range [][]ssoconfig.GroupRole{nil, in[:1], in} {
			gotClaim, got, reason := validGroupMapping(claim, mappings)
			if reason != "" {
				if gotClaim != "" || got != nil {
					t.Fatalf("a refusal (%s) returned a mapping: %q %v", reason, gotClaim, got)
				}
				continue
			}
			if gotClaim != strings.TrimSpace(claim) || utf8.RuneCountInString(gotClaim) > maxGroupFieldLen {
				t.Fatalf("accepted claim %q from %q", gotClaim, claim)
			}
			if (gotClaim == "") != (len(got) == 0) || len(got) != len(mappings) {
				t.Fatalf("accepted claim %q with %d of %d mappings", gotClaim, len(got), len(mappings))
			}
			seen := map[string]bool{}
			for i, gr := range got {
				if gr.Group == "" || gr.Group != strings.TrimSpace(mappings[i].Group) || utf8.RuneCountInString(gr.Group) > maxGroupFieldLen {
					t.Fatalf("accepted group %q from %q", gr.Group, mappings[i].Group)
				}
				if seen[gr.Group] {
					t.Fatalf("accepted %q twice", gr.Group)
				}
				seen[gr.Group] = true
				if !rbac.GrantableRoles[gr.Role] || gr.Role != strings.ToLower(strings.TrimSpace(mappings[i].Role)) {
					t.Fatalf("accepted role %q from %q", gr.Role, mappings[i].Role)
				}
			}
		}
	})
}
