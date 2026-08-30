package sigmabind

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// TestEndToEnd_KeychainDumpShape walks the whole path a rule takes: compile a detection block, check its fields against the
// taxonomy, then match it against events in the shape a real host produces. The rule mirrors credential_keychain_dump, one of the
// detections #761 converts, so this is the first evidence that a Sigma rule can express a detection we already ship.
//
// The rule text is written here rather than copied from SigmaHQ, whose content carries the Detection Rule License.
func TestEndToEnd_KeychainDumpShape(t *testing.T) {
	t.Parallel()

	rule := compile(t, `
selection:
  Image|endswith: '/security'
  CommandLine|contains: ' dump-keychain'
condition: selection
`)
	require.NoError(t, Validate(rule, "exec"), "every field must be one we supply")

	cases := []struct {
		name    string
		payload string
		want    bool
	}{
		{
			"the real invocation fires",
			`{"pid":501,"ppid":1,"path":"/usr/bin/security","args":["security","dump-keychain","-d"]}`, true,
		},
		{
			"a different security subcommand does not",
			`{"pid":501,"ppid":1,"path":"/usr/bin/security","args":["security","find-certificate"]}`, false,
		},
		{
			"a different binary does not, even with matching arguments",
			`{"pid":501,"ppid":1,"path":"/bin/echo","args":["echo","dump-keychain"]}`, false,
		},
		{
			// Image is the resolved path, so a hand-crafted argv[0] cannot spoof the binary check.
			"a spoofed argv[0] does not fire",
			`{"pid":501,"ppid":1,"path":"/tmp/evil","args":["/usr/bin/security","dump-keychain"]}`, false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, err := NewEvent(api.Event{EventID: "e1", EventType: "exec", Payload: []byte(tc.payload)})
			require.NoError(t, err)
			assert.Equal(t, tc.want, rule.Matches(e))
		})
	}
}

// TestEndToEnd_FileEventShape covers the other mapped category, in the shape of a sudoers-tamper detection.
func TestEndToEnd_FileEventShape(t *testing.T) {
	t.Parallel()

	rule := compile(t, `
selection:
  TargetFilename|startswith: '/etc/sudoers'
filter_readonly:
  TargetFilename|endswith: '.bak'
condition: selection and not filter_readonly
`)
	require.NoError(t, Validate(rule, "open"))

	fires := func(path string) bool {
		e, err := NewEvent(api.Event{EventID: "e1", EventType: "open", Payload: []byte(`{"pid":1,"path":"` + path + `","flags":2}`)})
		require.NoError(t, err)
		return rule.Matches(e)
	}
	assert.True(t, fires("/etc/sudoers"))
	assert.True(t, fires("/etc/sudoers.d/99-evil"))
	assert.False(t, fires("/etc/sudoers.bak"), "the filter suppresses")
	assert.False(t, fires("/etc/passwd"))
}

// spec:server-detection-rules-engine/our-events-supply-the-sigma-fields-a-rule-reads/a-rule-is-inert-against-an-event-type-it-does-not-name
//
// TestEndToEnd_RuleForTheWrongEventTypeSuppliesNothing pins that a rule is inert against an event type it was not validated for,
// rather than matching by accident. Dispatching rules by event type is #762; until then this is the property that keeps a
// misrouted rule from producing a wrong finding.
func TestEndToEnd_RuleForTheWrongEventTypeSuppliesNothing(t *testing.T) {
	t.Parallel()

	rule := compile(t, "selection:\n  Image|endswith: '/security'\ncondition: selection\n")
	e, err := NewEvent(api.Event{EventID: "e1", EventType: "open", Payload: []byte(`{"pid":1,"path":"/usr/bin/security","flags":0}`)})
	require.NoError(t, err)
	assert.False(t, rule.Matches(e), "an exec rule must not match an open event that happens to carry the same path")
}
