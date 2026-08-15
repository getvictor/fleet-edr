package catalog

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// alertsSubjectColumnLen mirrors alerts.subject VARCHAR(255) in the detection schema. Duplicated here rather than imported
// because the rules package must not depend on the store; the test's job is to notice if the two ever disagree.
const alertsSubjectColumnLen = 255

// spec:server-detection-rules-engine/edr-sensor-tamper-detection/a-capture-provider-stops-and-does-not-resume
//
// TestProviderSubject_FitsTheColumnForAnyProvider is the reason this helper exists. The provider arrives in agent-supplied
// JSON and is never length-checked at ingest, and a subject the column cannot hold fails the INSERT, which aborts the whole
// batch's evaluation rather than just losing one alert.
func TestProviderSubject_FitsTheColumnForAnyProvider(t *testing.T) {
	t.Parallel()
	const eventID = "8f14e45f-ceea-467a-9a3d-4c1b2e5f9a71" // a v4 UUID, the real shape
	cases := []struct {
		name     string
		provider string
	}{
		{"a real provider", "content_filter"},
		{"empty", ""},
		{"absurdly long", strings.Repeat("a", 10_000)},
		{"long and multi-byte", strings.Repeat("提供者", 3_000)},
		{"long with the separator repeated", strings.Repeat(":", 5_000)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, prefix := range []string{"sensor_stop", "sensor_recovery_failed"} {
				got := providerSubject(prefix, tc.provider, eventID)
				assert.LessOrEqual(t, len([]rune(got)), alertsSubjectColumnLen,
					"%s subject must fit the column", prefix)
				assert.True(t, utf8.ValidString(got), "trimming must not cut a multi-byte character in half")
				assert.Contains(t, got, eventID, "the event id must survive whole; it is what makes the subject unique")
			}
		})
	}
}

// TestProviderSubject_KeepsDistinctRecordsDistinct pins the property that makes trimming safe at all. If two separate
// incidents could collapse onto one subject, dedup would silently suppress a real alert, which is a worse failure than the
// oversized-insert this bound prevents.
func TestProviderSubject_KeepsDistinctRecordsDistinct(t *testing.T) {
	t.Parallel()
	// Two providers identical for far longer than the cap, so the trimmed portions are byte-for-byte equal and ONLY the
	// event id can tell the subjects apart.
	longA := strings.Repeat("x", 500) + "-alpha"
	longB := strings.Repeat("x", 500) + "-beta"

	first := providerSubject("sensor_stop", longA, "event-1")
	second := providerSubject("sensor_stop", longB, "event-2")
	assert.NotEqual(t, first, second, "different records must not collapse onto one dedup subject")

	// And the same record must still collapse, which is what dedup depends on.
	assert.Equal(t, first, providerSubject("sensor_stop", longA, "event-1"),
		"re-evaluating one record must produce the same subject")
}

// TestProviderSubject_LeavesRealProvidersUntouched guards the ordinary path: the bound must be invisible in practice, or
// operators would see mangled provider names in their alerts.
func TestProviderSubject_LeavesRealProvidersUntouched(t *testing.T) {
	t.Parallel()
	for _, provider := range []string{"content_filter", "dns_proxy"} {
		require.Equal(t, "sensor_stop:"+provider+":e1", providerSubject("sensor_stop", provider, "e1"))
	}
}
