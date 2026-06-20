package ssoconfig_test

import (
	"testing"

	"github.com/fleetdm/edr/server/identity/internal/ssoconfig"
	"github.com/stretchr/testify/assert"
)

func TestRedirectURLFor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		external string
		want     string
	}{
		{"empty base is empty", "", ""},
		{"plain base", "https://edr.acme.com", "https://edr.acme.com/api/auth/callback"},
		{"single trailing slash tolerated", "https://edr.acme.com/", "https://edr.acme.com/api/auth/callback"},
		{"multiple trailing slashes tolerated", "https://edr.acme.com///", "https://edr.acme.com/api/auth/callback"},
		{"subpath preserved", "https://acme.com/edr", "https://acme.com/edr/api/auth/callback"},
		{"query is dropped not concatenated", "https://edr.acme.com?x=1", "https://edr.acme.com/api/auth/callback"},
		{"fragment is dropped not concatenated", "https://edr.acme.com#frag", "https://edr.acme.com/api/auth/callback"},
		{"query and fragment both dropped", "https://edr.acme.com/?x=1#frag", "https://edr.acme.com/api/auth/callback"},
		{"bare trailing query marker dropped", "https://edr.acme.com?", "https://edr.acme.com/api/auth/callback"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, ssoconfig.RedirectURLFor(tc.external))
		})
	}
}
