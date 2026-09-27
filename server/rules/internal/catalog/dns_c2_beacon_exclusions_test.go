package catalog

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/rules/api"
)

const beaconExclusionPID = 4242

// beaconExclusionBatch is one resolve-then-connect that fires with no exclusion: a process run from a temporary path looks up
// queryName and connects to the address it returned. The process is signed by team TEAM000001 with a cdhash, so every process
// dimension has a value to match on, unless codeSigning overrides the signature.
func beaconExclusionBatch(queryName, codeSigning string) (*perPIDGraphReader, api.Event) {
	cdhash := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	proc := &api.Process{
		ID: 7, HostID: "fixture-host", PID: beaconExclusionPID, Path: "/private/tmp/loadgen/osquery-perf",
		CodeSigning: detectionapi.NullRawJSON(codeSigning), CDHash: &cdhash,
	}
	lookup := api.Event{
		EventID: "beacon-exclusion-dns", HostID: "fixture-host", EventType: "dns_query", TimestampNs: 500,
		Payload: json.RawMessage(`{"pid":4242,"query_name":"` + queryName + `","response_addresses":["203.0.113.66"]}`),
	}
	connect := api.Event{
		EventID: "beacon-exclusion-connect", HostID: "fixture-host", EventType: "network_connect", TimestampNs: 1000,
		Payload: json.RawMessage(`{"pid":4242,"direction":"outbound","remote_address":"203.0.113.66","remote_port":443}`),
	}
	gr := &perPIDGraphReader{
		procByPID:      map[int]*api.Process{beaconExclusionPID: proc},
		netEventsByPID: map[int][]api.Event{beaconExclusionPID: {lookup, connect}},
	}
	return gr, connect
}

const signedByTeam = `{"team_id":"TEAM000001","signing_id":"com.example.loadgen","is_platform_binary":false}`

func evaluateBeaconWith(t *testing.T, excl api.ExclusionResolver, queryName, codeSigning string) []api.Finding {
	t.Helper()
	gr, connect := beaconExclusionBatch(queryName, codeSigning)
	findings, err := (&DNSC2Beacon{Exclusions: excl}).Evaluate(t.Context(), []api.Event{connect}, gr)
	require.NoError(t, err)
	return findings
}

// The control for every case below: without it, a fixture that failed the suspicion gate or the join would make each "no finding"
// assertion pass for a reason that has nothing to do with exclusions.
func TestDNSC2BeaconExclusions_TheFixtureFiresWithoutAnExclusion(t *testing.T) {
	t.Parallel()
	assert.Len(t, evaluateBeaconWith(t, &fakeExclusions{}, "loadtest.example.com", signedByTeam), 1)
	assert.Len(t, evaluateBeaconWith(t, nil, "loadtest.example.com", signedByTeam), 1, "a nil resolver excludes nothing")
}

// spec:server-detection-rules-engine/beacon-exclusions-by-domain-or-program/a-domain-exclusion-waives-that-domain-and-its-subdomains
// spec:server-detection-rules-engine/beacon-exclusions-by-domain-or-program/a-domain-exclusion-does-not-waive-a-different-domain
func TestDNSC2BeaconExclusions_Domain(t *testing.T) {
	t.Parallel()
	excl := &fakeExclusions{entries: []fakeExcl{{ruleID: "dns_c2_beacon", matchType: api.ExclusionMatchDomain, value: "example.com"}}}
	cases := []struct {
		name      string
		queryName string
		fires     bool
	}{
		{name: "the domain itself", queryName: "example.com", fires: false},
		{name: "a subdomain", queryName: "fleet-victor-apm-off.loadtest.example.com", fires: false},
		{name: "a name that only ends in the same letters", queryName: "notexample.com", fires: true},
		{name: "an unrelated domain", queryName: "kx7gq2vphj9k3mzw.example.net", fires: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			findings := evaluateBeaconWith(t, excl, tc.queryName, signedByTeam)
			if tc.fires {
				assert.Len(t, findings, 1)
			} else {
				assert.Empty(t, findings)
			}
		})
	}
}

// spec:server-detection-rules-engine/beacon-exclusions-by-domain-or-program/a-program-is-waived-by-path-or-code-signature
func TestDNSC2BeaconExclusions_Program(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		excl  fakeExcl
		fires bool
	}{
		// The process path is reported in the /private form; the public form must match it too, as it does for every path glob.
		{name: "path glob in the public form", excl: fakeExcl{matchType: api.ExclusionMatchPathGlob, value: "/tmp/loadgen/*"}},
		{name: "team id", excl: fakeExcl{matchType: api.ExclusionMatchTeamID, value: "TEAM000001"}},
		{name: "qualified signing id", excl: fakeExcl{matchType: api.ExclusionMatchSigningID, value: "TEAM000001:com.example.loadgen"}},
		{name: "cdhash", excl: fakeExcl{matchType: api.ExclusionMatchCDHash, value: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
		{name: "another program's path", excl: fakeExcl{matchType: api.ExclusionMatchPathGlob, value: "/tmp/other/*"}, fires: true},
		{name: "another team", excl: fakeExcl{matchType: api.ExclusionMatchTeamID, value: "TEAM000002"}, fires: true},
		// A parent_path_glob is suspicious_exec's dimension. This rule has no parent in play, and reading one as the subject's path
		// would let an exclusion saved for one meaning apply under another.
		{name: "a parent path glob", excl: fakeExcl{matchType: api.ExclusionMatchParentPathGlob, value: "/tmp/loadgen/*"}, fires: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.excl.ruleID = "dns_c2_beacon"
			findings := evaluateBeaconWith(t, &fakeExclusions{entries: []fakeExcl{tc.excl}}, "loadtest.example.com", signedByTeam)
			if tc.fires {
				assert.Len(t, findings, 1)
			} else {
				assert.Empty(t, findings)
			}
		})
	}
}

// spec:server-detection-rules-engine/beacon-exclusions-by-domain-or-program/an-ad-hoc-binary-cannot-claim-a-vendor-signing-id
//
// The planted-binary case #1024 closed for suspicious_exec, which this rule inherits by sharing processExcluded. An ad-hoc signature
// can claim any identifier; with no team it composes to no qualified identifier, so neither the qualified exclusion nor a bare one
// written the pre-#1024 way can match it.
func TestDNSC2BeaconExclusions_AnAdHocBinaryCannotClaimAVendorSigningID(t *testing.T) {
	t.Parallel()
	adHoc := `{"team_id":"","signing_id":"com.example.loadgen","is_platform_binary":false}`
	for _, value := range []string{"TEAM000001:com.example.loadgen", "com.example.loadgen"} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			excl := &fakeExclusions{entries: []fakeExcl{{ruleID: "dns_c2_beacon", matchType: api.ExclusionMatchSigningID, value: value}}}
			assert.Len(t, evaluateBeaconWith(t, excl, "loadtest.example.com", adHoc), 1)
		})
	}
}

// Exclusions are keyed by rule id. One saved for suspicious_exec on the same program must not silence this rule, or tuning one rule
// would quietly tune another.
func TestDNSC2BeaconExclusions_AnotherRulesExclusionDoesNotApply(t *testing.T) {
	t.Parallel()
	excl := &fakeExclusions{entries: []fakeExcl{{ruleID: "suspicious_exec", matchType: api.ExclusionMatchTeamID, value: "TEAM000001"}}}
	assert.Len(t, evaluateBeaconWith(t, excl, "loadtest.example.com", signedByTeam), 1)
}

// The consultation guard TestExclusionMatchTypes_NoUndeclaredConsultation applies to suspicious_exec, applied here: a signed process
// and a resolved domain reach every check, so the set the rule queries must equal the set it declares, no more and no less.
func TestDNSC2BeaconExclusions_ConsultsExactlyWhatItDeclares(t *testing.T) {
	t.Parallel()
	rec := newRecordingResolver()
	gr, connect := beaconExclusionBatch("loadtest.example.com", signedByTeam)
	rule := &DNSC2Beacon{Exclusions: rec}
	_, err := rule.Evaluate(t.Context(), []api.Event{connect}, gr)
	require.NoError(t, err)

	var queried []api.ExclusionMatchType
	for mt := range rec.queried[rule.ID()] {
		queried = append(queried, mt)
	}
	assert.ElementsMatch(t, rule.SupportedExclusionMatchTypes(), queried)
	assert.Equal(t, []string{rule.ID()}, slices.Collect(func(yield func(string) bool) {
		for id := range rec.queried {
			if !yield(id) {
				return
			}
		}
	}), "the rule must query only under its own id")
}
