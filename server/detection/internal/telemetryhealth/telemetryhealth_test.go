package telemetryhealth_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/telemetryhealth"
	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// componentsJSON builds the wire payload a host posts, which is what ParseClaims actually receives.
func componentsJSON(t *testing.T, comps ...endpointapi.ComponentHealth) []byte {
	t.Helper()
	raw, err := json.Marshal(comps)
	require.NoError(t, err)
	return raw
}

// provider is a shorthand for one capture provider's reported condition.
func provider(name string, status endpointapi.HealthStatus) endpointapi.ComponentHealth {
	return endpointapi.ComponentHealth{Type: name, Status: status, Reason: "activated"}
}

// bothCapturing is the ordinary healthy claim: the host says each provider is doing its job.
func bothCapturing(t *testing.T) telemetryhealth.Claims {
	t.Helper()
	return telemetryhealth.ParseClaims(componentsJSON(t,
		provider("content_filter", endpointapi.HealthHealthy),
		provider("dns_proxy", endpointapi.HealthHealthy),
	))
}

// wedged is the activity shape of the incident this package exists for: process telemetry flowing, both flow streams silent.
func wedged() visibilityapi.TelemetryActivity {
	return visibilityapi.TelemetryActivity{ProcessInWindow: 1204, ConnectInWindow: 0, DNSInWindow: 0}
}

// The non-accusation cases are the ones that decide whether this signal is usable at all: a check that cries wolf on idle
// laptops gets muted, and a muted check detects nothing.
//
// spec:server-host-status/the-server-derives-health-conditions-its-endpoints-cannot-report/an-idle-host-is-not-accused
// spec:server-host-status/the-server-derives-health-conditions-its-endpoints-cannot-report/a-provider-the-host-does-not-claim-is-not-accused
// spec:server-host-status/the-server-derives-health-conditions-its-endpoints-cannot-report/a-host-already-reporting-a-fault-gains-no-second-condition
func TestDerive(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		claims   func(*testing.T) telemetryhealth.Claims
		activity visibilityapi.TelemetryActivity
		want     []string
	}{
		{
			name:     "both providers claim to be capturing and both streams are silent",
			claims:   bothCapturing,
			activity: wedged(),
			want:     []string{"content_filter_delivery", "dns_proxy_delivery"},
		},
		{
			name:     "only the silent stream's provider is reported",
			claims:   bothCapturing,
			activity: visibilityapi.TelemetryActivity{ProcessInWindow: 500, ConnectInWindow: 771, DNSInWindow: 0},
			want:     []string{"dns_proxy_delivery"},
		},
		{
			name:     "everything flowing",
			claims:   bothCapturing,
			activity: visibilityapi.TelemetryActivity{ProcessInWindow: 500, ConnectInWindow: 771, DNSInWindow: 123},
			want:     nil,
		},
		{
			// The false-positive case that matters most (issue #677 QA step 1): a host doing nothing produces no flows, and
			// that is not a fault. The claims are deliberately present here, so ONLY the process gate can be rejecting it.
			name:     "idle host with no process activity is not accused",
			claims:   bothCapturing,
			activity: visibilityapi.TelemetryActivity{},
			want:     nil,
		},
		{
			// The case that used to need seven days of history to answer (issue #702). The agent omits a provider the
			// operator disabled, so there is simply no claim about it, and silence about it means nothing.
			name: "a provider the host does not claim is not accused",
			claims: func(t *testing.T) telemetryhealth.Claims {
				t.Helper()
				return telemetryhealth.ParseClaims(componentsJSON(t, provider("content_filter", endpointapi.HealthHealthy)))
			},
			activity: wedged(),
			want:     []string{"content_filter_delivery"},
		},
		{
			// The endpoint already reports these as stopped, so a derived condition would be a redundant second opinion on
			// a fault the operator can already see.
			name: "a provider the endpoint already reports stopped gains no second condition",
			claims: func(t *testing.T) telemetryhealth.Claims {
				t.Helper()
				return telemetryhealth.ParseClaims(componentsJSON(t,
					provider("content_filter", endpointapi.HealthUnhealthy),
					provider("dns_proxy", endpointapi.HealthUnhealthy),
				))
			},
			activity: wedged(),
			want:     nil,
		},
		{
			name: "a host claiming nothing at all",
			claims: func(*testing.T) telemetryhealth.Claims {
				return telemetryhealth.ParseClaims(nil)
			},
			activity: wedged(),
			want:     nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var types []string
			for _, c := range telemetryhealth.Derive(tc.claims(t), tc.activity) {
				types = append(types, c.Type)
			}
			assert.Equal(t, tc.want, types)
		})
	}
}

// TestParseClaims pins exactly which reported conditions count as a claim, which is now the entire gate. Reading one too
// broadly manufactures findings on hosts that asserted nothing; reading one too narrowly switches the detection off.
func TestParseClaims(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		comps []endpointapi.ComponentHealth
		want  []string // derived conditions the claim licenses, given a wedged telemetry shape
	}{
		{
			name:  "a capturing provider claims",
			comps: []endpointapi.ComponentHealth{provider("dns_proxy", endpointapi.HealthHealthy)},
			want:  []string{"dns_proxy_delivery"},
		},
		{
			name:  "a stopped provider does not",
			comps: []endpointapi.ComponentHealth{provider("dns_proxy", endpointapi.HealthUnhealthy)},
			want:  nil,
		},
		{
			name:  "a provider in an unrecognised state does not",
			comps: []endpointapi.ComponentHealth{provider("dns_proxy", endpointapi.HealthUnknown)},
			want:  nil,
		},
		{
			// The extensions themselves are healthy on nearly every host. Treating them as provider claims would fire on
			// every host that simply is not making DNS queries.
			name: "a healthy component that is not a provider does not",
			comps: []endpointapi.ComponentHealth{
				provider("network_extension", endpointapi.HealthHealthy),
				provider("endpoint_security_extension", endpointapi.HealthHealthy),
			},
			want: nil,
		},
		{
			name: "the providers are read independently of each other",
			comps: []endpointapi.ComponentHealth{
				provider("content_filter", endpointapi.HealthHealthy),
				provider("dns_proxy", endpointapi.HealthUnhealthy),
			},
			want: []string{"content_filter_delivery"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			claims := telemetryhealth.ParseClaims(componentsJSON(t, tc.comps...))

			// Asserted THROUGH Derive rather than through an accessor, because what a claim means is exactly what it
			// licenses: an accessor could agree while the derivation ignored it.
			var got []string
			for _, c := range telemetryhealth.Derive(claims, wedged()) {
				got = append(got, c.Type)
			}
			assert.Equal(t, tc.want, got)
			assert.Equal(t, len(tc.want) > 0, claims.Any(), "Any must agree with whether any claim was honoured")
		})
	}
}

// TestParseClaims_UnreadablePayloadClaimsNothing covers the payloads this cannot interpret. Guessing would be wrong in the
// accusing direction, so an undecodable snapshot must assert nothing.
func TestParseClaims_UnreadablePayloadClaimsNothing(t *testing.T) {
	t.Parallel()
	for _, raw := range [][]byte{nil, {}, []byte("not json"), []byte(`{"not":"an array"}`), []byte(`[`)} {
		claims := telemetryhealth.ParseClaims(raw)
		assert.False(t, claims.Any(), "payload %q must claim nothing", raw)
		assert.Empty(t, telemetryhealth.Derive(claims, wedged()))
	}
}

// TestDerive_ConditionShape pins what an operator actually reads, since a finding nobody can act on is not worth raising.
func TestDerive_ConditionShape(t *testing.T) {
	t.Parallel()
	got := telemetryhealth.Derive(bothCapturing(t), wedged())
	require.Len(t, got, 2)

	dns := got[1]
	assert.Equal(t, "dns_proxy_delivery", dns.Type)
	assert.Equal(t, string(endpointapi.HealthDegraded), dns.Status,
		"degraded, not unhealthy: this is inferred from absence, not observed by the endpoint")
	assert.Equal(t, telemetryhealth.ReasonNoFlowTelemetry, dns.Reason)
	assert.Contains(t, dns.Message, "dns_query", "the message must name the stream that went silent")
	assert.Contains(t, dns.Message, "dns_proxy", "the message must name the provider to remediate")
	assert.Contains(t, dns.Message, "1204", "the message must carry the evidence the host was not merely idle")
	assert.Contains(t, dns.Message, "2h", "the window is stated so an operator knows what 'no events' covers")
	assert.NotContains(t, dns.Message, "2h0m0s", "Go's duration spelling reads as machine output mid-sentence")
	assert.Zero(t, dns.LastTransitionNs,
		"a window count cannot recover the instant the stream fell silent, and a stamped 'now' would date a days-old fault to page load")
}

func TestRollup(t *testing.T) {
	t.Parallel()
	degraded := []api.DerivedComponent{{Type: "dns_proxy_delivery", Status: string(endpointapi.HealthDegraded)}}
	cases := []struct {
		name     string
		reported string
		derived  []api.DerivedComponent
		want     string
	}{
		{
			name:     "nothing derived leaves the reported rollup exactly as it was",
			reported: string(endpointapi.HealthHealthy),
			derived:  nil,
			want:     string(endpointapi.HealthHealthy),
		},
		{
			name:     "a derived condition degrades a healthy host",
			reported: string(endpointapi.HealthHealthy),
			derived:  degraded,
			want:     string(endpointapi.HealthDegraded),
		},
		{
			// Reachable now that the gate is per provider rather than the rollup: a host can be unhealthy for an unrelated
			// component while one provider still claims to be capturing. The fold must not DOWNGRADE the reported fault.
			name:     "a derived condition never downgrades a worse reported state",
			reported: string(endpointapi.HealthUnhealthy),
			derived:  degraded,
			want:     string(endpointapi.HealthUnhealthy),
		},
		{
			name:     "a derived condition beats an unknown rollup",
			reported: string(endpointapi.HealthUnknown),
			derived:  degraded,
			want:     string(endpointapi.HealthDegraded),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, telemetryhealth.Rollup(tc.reported, tc.derived))
		})
	}
}

// TestWindow pins the bound the archive read uses.
func TestWindow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 11, 20, 0, 0, time.UTC)
	w := telemetryhealth.Window(now)

	assert.Equal(t, now.UnixNano(), w.ToNs, "the read must not look past now, or a future-stamped event masks a real fault")
	assert.Equal(t, now.Add(-telemetryhealth.SilenceWindow).UnixNano(), w.FromNs)
}

// TestSilenceWindowIsMeasured guards the constant against a well-meaning edit.
//
// It is not a preference. Over 30 days of the dogfood host's archive, benign flow silence never exceeded 30 minutes while the
// real wedge ran for days. An edit that violates that bound is a behaviour change needing its own measurement, not a tweak.
func TestSilenceWindowIsMeasured(t *testing.T) {
	t.Parallel()
	assert.Greater(t, telemetryhealth.SilenceWindow, 30*time.Minute,
		"the silence window must exceed the longest benign silence observed (30 minutes) or healthy hosts will be accused")
	assert.Less(t, telemetryhealth.SilenceWindow, 12*time.Hour,
		"and stay short enough that a wedge is not invisible for most of a day")
}
