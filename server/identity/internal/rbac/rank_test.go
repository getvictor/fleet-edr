package rbac_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/identity/internal/rbac"
)

// MostPrivileged ranks the seeded roles super_admin, admin, senior_analyst, analyst, auditor, and any other role below all of them.
func TestMostPrivileged(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		roles []string
		want  string
	}{
		{"super admin over admin", []string{"admin", "super_admin"}, "super_admin"},
		{"admin over senior analyst", []string{"senior_analyst", "admin"}, "admin"},
		{"senior analyst over analyst", []string{"analyst", "senior_analyst"}, "senior_analyst"},
		{"analyst over auditor", []string{"auditor", "analyst"}, "analyst"},
		{"a seeded role over an unknown one", []string{"custom", "auditor"}, "auditor"},
		{"an unknown role alone", []string{"custom"}, "custom"},
		{"none", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, rbac.MostPrivileged(tc.roles))
		})
	}
}
