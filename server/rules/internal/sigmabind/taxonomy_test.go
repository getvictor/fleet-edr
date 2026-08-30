package sigmabind

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/fleetdm/edr/server/rules/internal/export"
	"github.com/fleetdm/edr/server/rules/internal/sigma"
)

func compile(t *testing.T, detection string) *sigma.Rule {
	t.Helper()
	var doc map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(detection), &doc))
	r, err := sigma.Compile(doc)
	require.NoError(t, err)
	return r
}

// TestValidate_AcceptsMappedFields covers the fields the corpus actually reads and we can supply.
func TestValidate_AcceptsMappedFields(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		eventType string
		detection string
	}{
		{"exec image", "exec", "selection:\n  Image|endswith: '/curl'\ncondition: selection\n"},
		{"exec command line", "exec", "selection:\n  CommandLine|contains: 'dump-keychain'\ncondition: selection\n"},
		{"exec both", "exec", "selection:\n  Image|endswith: '/security'\n  CommandLine|contains: 'dump'\ncondition: selection\n"},
		{"open target filename", "open", "selection:\n  TargetFilename|contains: '/etc/sudoers'\ncondition: selection\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.NoError(t, Validate(compile(t, tc.detection), tc.eventType))
		})
	}
}

// spec:server-detection-rules-engine/a-rule-reading-a-field-we-do-not-supply-is-refused-when-it-loads/a-rule-reading-a-field-we-do-not-supply-is-refused
//
// TestValidate_RejectsUnmappedFields is the load-time half of the evaluator's contract. A rule reading a field we never populate
// evaluates to false on that field for every event forever, which is indistinguishable from the behaviour never occurring.
func TestValidate_RejectsUnmappedFields(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		eventType string
		detection string
		want      string
	}{
		{
			// 16 of the 69 macOS corpus rules read ParentImage. They are meant to fail here until #771 lands the enrichment.
			"ParentImage needs the enrichment in #771", "exec",
			"selection:\n  ParentImage|endswith: '/bash'\ncondition: selection\n", "ParentImage",
		},
		{
			// A Windows PE version-resource field with no macOS equivalent, so no enrichment will ever supply it.
			"OriginalFileName has no macOS equivalent", "exec",
			"selection:\n  OriginalFileName: 'curl.exe'\ncondition: selection\n", "OriginalFileName",
		},
		{
			"a field of another event type is not silently accepted", "open",
			"selection:\n  CommandLine|contains: 'x'\ncondition: selection\n", "CommandLine",
		},
		{
			"an unknown field", "exec",
			"selection:\n  NoSuchField: 'x'\ncondition: selection\n", "NoSuchField",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := Validate(compile(t, tc.detection), tc.eventType)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.Contains(t, err.Error(), "supported:", "the error names what IS available, so the reader can act on it")
		})
	}
}

// TestValidate_RejectsUnmappedEventType keeps a rule for a type we supply nothing for from reading as "no missing fields".
func TestValidate_RejectsUnmappedEventType(t *testing.T) {
	t.Parallel()

	err := Validate(compile(t, "selection:\n  Image: '/bin/sh'\ncondition: selection\n"), "dns_query")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no Sigma field mapping")
	assert.Contains(t, err.Error(), "dns_query")
}

// TestValidate_RejectsNilRule covers the guard rather than leaving a nil dereference in a load path.
func TestValidate_RejectsNilRule(t *testing.T) {
	t.Parallel()

	require.Error(t, Validate(nil, "exec"))
}

// TestSupportedFields pins the mapped set. Asserted exactly, not by length: this is the list that decides which corpus rules can
// load at all, so silently gaining or losing one should fail here.
func TestSupportedFields(t *testing.T) {
	t.Parallel()

	assert.Equal(t, []string{"CommandLine", "Image"}, SupportedFields("exec"))
	assert.Equal(t, []string{"TargetFilename"}, SupportedFields("open"))
	assert.Empty(t, SupportedFields("dns_query"))
	assert.Empty(t, SupportedFields("nonexistent"))
}

// TestEventTypeForCategory covers the logsource lookup a rule file goes through.
func TestEventTypeForCategory(t *testing.T) {
	t.Parallel()

	et, ok := EventTypeForCategory("process_creation")
	assert.True(t, ok)
	assert.Equal(t, "exec", et)

	et, ok = EventTypeForCategory("file_event")
	assert.True(t, ok)
	assert.Equal(t, "open", et)

	_, ok = EventTypeForCategory("registry_set")
	assert.False(t, ok, "a category we cannot supply fields for must not resolve")
}

// TestCategoryMappingAgreesWithTheExporter is the drift guard between the two directions of one correspondence. The exporter maps
// our event type onto a Sigma category when it WRITES a rule file; this package maps the category back when it EVALUATES one. If
// they ever disagree, we would emit files under a category we then refuse to evaluate, and the mistake would surface as rules that
// silently never run.
func TestCategoryMappingAgreesWithTheExporter(t *testing.T) {
	t.Parallel()

	for category, eventType := range sigmaCategoryToEventType {
		forward, ok := export.SigmaCategory(eventType)
		require.True(t, ok, "exporter has no category for event type %q", eventType)
		assert.Equal(t, category, forward,
			"exporter writes %q as %q but this package reads %q back as %q", eventType, forward, category, eventType)
	}
}
