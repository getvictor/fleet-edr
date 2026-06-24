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
	t.Parallel()
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
			t.Parallel()
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

// spec:endpoint-event-collection/canonical-event-envelope/events-from-the-same-device-share-a-host-id
//
// The spec's two clauses are "every emitted event carries the same host_id" and "that value persists across
// reboots." Both clauses bottom out on the same property: the host_id returned by Get() is sourced from
// IOPlatformUUID, which the macOS kernel reads from hardware and is stable across reboots of that device.
// This test pins the determinism of the source: feeding Get a known IOPlatformUUID line returns that exact
// UUID, so any caller that stamps Get()'s result onto every event envelope satisfies both spec clauses.
// The stamping side is exercised by the reconcile_test.go tests that emit envelopes carrying env.HostID.
//
// TestGet_FromFakeIOReg drives the Get() shell-out path. Real ioreg only runs on macOS and emits non-deterministic data, so we point
// ioregPath at a tiny shell wrapper that prints a known IOPlatformUUID line. This is the only way to cover the success path of Get
// without making the test host-dependent.
func TestGet_FromFakeIOReg(t *testing.T) { //nolint:paralleltest // mutates package-level ioregPath; Get tests serial (issue #172)
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

// TestGet_ExecError exercises the failure-wrapping branch when ioreg cannot be launched at all (missing binary). The error must
// mention "run ioreg" so log readers can diagnose.
func TestGet_ExecError(t *testing.T) { //nolint:paralleltest // mutates package-level ioregPath; Get tests serial (issue #172)
	orig := ioregPath
	ioregPath = filepath.Join(t.TempDir(), "does-not-exist")
	t.Cleanup(func() { ioregPath = orig })

	_, err := Get(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "run ioreg")
}

// FuzzParseIORegOutput drives the regex-based parser with random bytes. The invariant we care about is "must not panic on any input".
// A malformed ioreg(1) output (truncated buffer, encoding glitch) should turn into a "not found" error, never crash the agent's
// startup path.
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
// missing the IOPlatformUUID line: Get bubbles up the parse error verbatim.
func TestGet_NoUUIDInOutput(t *testing.T) { //nolint:paralleltest // mutates package-level ioregPath; Get tests serial (issue #172)
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
