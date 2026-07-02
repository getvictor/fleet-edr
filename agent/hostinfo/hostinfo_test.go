package hostinfo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollect_ParsesSystemVersionFixture(t *testing.T) {
	t.Parallel()
	info := collect(filepath.Join("testdata", "SystemVersion.plist"))

	hostname, err := os.Hostname()
	require.NoError(t, err)
	assert.Equal(t, hostname, info.Hostname)
	assert.Equal(t, "macOS", info.OSName)
	assert.Equal(t, "26.4", info.OSVersion)
	assert.Equal(t, "25E123", info.OSBuild)
}

// spec:agent-status-reporting/status-report-carries-host-inventory/missing-os-metadata-degrades-to-empty-fields
func TestCollect_MissingPlistDegradesToEmptyOSFields(t *testing.T) {
	t.Parallel()
	info := collect(filepath.Join(t.TempDir(), "does-not-exist.plist"))

	assert.NotEmpty(t, info.Hostname, "hostname comes from the kernel, not the plist")
	assert.Empty(t, info.OSName)
	assert.Empty(t, info.OSVersion)
	assert.Empty(t, info.OSBuild)
}

func TestParseStringPlist(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want map[string]string
	}{
		{
			name: "flat dict of key string pairs",
			in:   `<plist><dict><key>A</key><string>1</string><key>B</key><string>2</string></dict></plist>`,
			want: map[string]string{"A": "1", "B": "2"},
		},
		{
			name: "non-string value clears the pending key",
			in:   `<plist><dict><key>N</key><integer>3</integer><key>S</key><string>ok</string></dict></plist>`,
			want: map[string]string{"S": "ok"},
		},
		{
			name: "empty document",
			in:   `<plist><dict></dict></plist>`,
			want: map[string]string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseStringPlist([]byte(tc.in))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseStringPlist_MalformedXML(t *testing.T) {
	t.Parallel()
	_, err := parseStringPlist([]byte(`<plist><dict><key>A</key>`))
	assert.Error(t, err)
}
