package hostid

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseIORegOutput(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name: "typical ioreg output",
			input: `+-o Root  <class IORegistryEntry, id 0x100000100, retain 32>
  +-o IOPlatformExpertDevice  <class IOPlatformExpertDevice, id 0x100000257, registered, matched, active, busy 0 (0 ms), retain 36>
      {
        "compatible" = <"MacBookPro18,2">
        "IOPlatformUUID" = "93DFC6F5-763D-5075-B305-8AC145D12F96"
        "IOPlatformSerialNumber" = "ABCDEF123456"
      }`,
			want: "93DFC6F5-763D-5075-B305-8AC145D12F96",
		},
		{
			name:  "tight spacing",
			input: `"IOPlatformUUID"="AAAA-BBBB"`,
			want:  "AAAA-BBBB",
		},
		{
			name:    "missing uuid",
			input:   `+-o IOPlatformExpertDevice { "compatible" = <"MacBookPro18,2"> }`,
			wantErr: true,
		},
		{
			name:    "empty",
			input:   ``,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseIORegOutput([]byte(tt.input))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestGet_FromFakeIOReg drives the Get() shell-out path. Real ioreg only runs
// on macOS and emits non-deterministic data, so we point ioregPath at a tiny
// shell wrapper that prints a known IOPlatformUUID line. This is the only way
// to cover the success path of Get without making the test host-dependent.
func TestGet_FromFakeIOReg(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-ioreg.sh")
	body := "#!/bin/sh\ncat <<'EOF'\n  \"IOPlatformUUID\" = \"FAKE-UUID-1234\"\nEOF\n"
	require.NoError(t, os.WriteFile(script, []byte(body), 0o600))
	// Test fixture: needs the executable bit so exec.CommandContext can run it.
	// The file lives only under t.TempDir(), wiped at the end of the test.
	require.NoError(t, os.Chmod(script, 0o700)) //nolint:gosec // exec bit required

	orig := ioregPath
	ioregPath = script
	t.Cleanup(func() { ioregPath = orig })

	got, err := Get(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "FAKE-UUID-1234", got)
}

// TestGet_ExecError exercises the failure-wrapping branch when ioreg cannot be
// launched at all (missing binary). The error must mention "run ioreg" so log
// readers can diagnose.
func TestGet_ExecError(t *testing.T) {
	orig := ioregPath
	ioregPath = filepath.Join(t.TempDir(), "does-not-exist")
	t.Cleanup(func() { ioregPath = orig })

	_, err := Get(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "run ioreg")
}

// FuzzParseIORegOutput drives the regex-based parser with random bytes. The
// invariant we care about is "must not panic on any input" — a malformed
// ioreg(1) output (truncated buffer, encoding glitch) should turn into a
// "not found" error, never crash the agent's startup path.
func FuzzParseIORegOutput(f *testing.F) {
	for _, seed := range []string{
		`"IOPlatformUUID" = "AAA"`,
		`"IOPlatformUUID"="BBB"`,
		`no uuid here`,
		``,
		`"IOPlatformUUID" = "" garbage`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		_, _ = parseIORegOutput(in)
	})
}

// TestGet_NoUUIDInOutput covers the case where ioreg ran but its output is
// missing the IOPlatformUUID line — Get bubbles up the parse error verbatim.
func TestGet_NoUUIDInOutput(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-ioreg-empty.sh")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\necho 'no uuid here'\n"), 0o600))
	require.NoError(t, os.Chmod(script, 0o700)) //nolint:gosec // exec bit required, file in t.TempDir

	orig := ioregPath
	ioregPath = script
	t.Cleanup(func() { ioregPath = orig })

	_, err := Get(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "IOPlatformUUID not found")
}
