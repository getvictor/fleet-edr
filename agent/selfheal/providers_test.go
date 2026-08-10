package selfheal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRemediable pins the eligibility filter. This is the safety-critical half of the feature: everything the filter lets
// through gets its system configuration rewritten by a root daemon without asking anyone, so a false positive here is the
// product overriding an operator's deliberate decision.
//
// spec:agent-status-reporting/remediation-never-overrides-a-deliberate-operator-decision/a-deliberately-disabled-provider-is-not-re-enabled
func TestRemediable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		desc      string
		providers map[string]string
		want      []string
	}{
		{
			desc:      "a stopped provider is eligible",
			providers: map[string]string{"content_filter": "stopped"},
			want:      []string{"content_filter"},
		},
		{
			// The #649 wire contract: an operator-disabled provider is ABSENT from the map, never "stopped". That is the
			// entire mechanism preventing self-heal from re-enabling the opt-in DNS proxy against the operator's wishes,
			// so it is asserted directly rather than inferred from the stopped case.
			desc:      "a deliberately disabled provider is absent, so nothing is eligible",
			providers: map[string]string{"content_filter": "running"},
			want:      []string{},
		},
		{
			desc:      "an empty report has nothing to remediate",
			providers: map[string]string{},
			want:      []string{},
		},
		{
			// The no-providers-running state (#649) is real and unhealthy, but there is no stopped provider to re-enable:
			// nothing ever started. Acting here would mean guessing which providers SHOULD be running, which is the
			// cause-based reasoning this design avoids.
			desc:      "a nil report is not a licence to guess",
			providers: nil,
			want:      []string{},
		},
		{
			desc:      "running providers are left alone",
			providers: map[string]string{"content_filter": "running", "dns_proxy": "running"},
			want:      []string{},
		},
		{
			desc:      "both stopped providers are eligible, sorted",
			providers: map[string]string{"dns_proxy": "stopped", "content_filter": "stopped"},
			want:      []string{"content_filter", "dns_proxy"},
		},
		{
			desc:      "only the stopped one of a mixed report is eligible",
			providers: map[string]string{"content_filter": "running", "dns_proxy": "stopped"},
			want:      []string{"dns_proxy"},
		},
		{
			// A provider this build has no enable subcommand for still reports unhealthy through health; it just is not
			// acted on. Silently mapping it to some other provider's subcommand would be worse than doing nothing.
			desc:      "an unknown provider is reported but not remediable",
			providers: map[string]string{"future_provider": "stopped"},
			want:      []string{},
		},
		{
			desc:      "an unrecognised state is not treated as stopped",
			providers: map[string]string{"content_filter": "wedged"},
			want:      []string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, Remediable(tc.providers))
		})
	}
}

func TestSubcommandMapsEveryRemediableProvider(t *testing.T) {
	t.Parallel()
	// These strings are the wire contract shared with the extension's ProviderLiveness.Provider raw values. A rename on
	// either side silently stops remediation, so pin them.
	for provider, want := range map[string]string{
		"content_filter": "enable-filter",
		"dns_proxy":      "enable-dns-proxy",
	} {
		got, ok := Subcommand(provider)
		assert.True(t, ok, provider)
		assert.Equal(t, want, got, provider)
	}
	_, ok := Subcommand("nope")
	assert.False(t, ok)
}
