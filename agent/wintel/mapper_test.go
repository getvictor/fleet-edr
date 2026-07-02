package wintel

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFiletimeToUnixNano(t *testing.T) {
	t.Parallel()
	// The FILETIME epoch offset itself is 1970-01-01, i.e. Unix 0.
	assert.Equal(t, int64(0), filetimeToUnixNano(filetimeEpochOffset))
	// Zero is treated as "unknown" -> 0 so omitempty drops it.
	assert.Equal(t, int64(0), filetimeToUnixNano(0))
	// One tick past the Unix epoch is 100 ns.
	assert.Equal(t, int64(100), filetimeToUnixNano(filetimeEpochOffset+1))
	// A real sample captured on the VM (createFT=134274934820033111) resolves to a plausible 2026 timestamp (> 1.7e18 ns).
	got := filetimeToUnixNano(134274934820033111)
	assert.Greater(t, got, int64(1_700_000_000_000_000_000))
}

// spec:windows-event-collection/windows-process-telemetry-via-etw/an-nt-device-image-path-is-reported-as-a-dos-path
func TestNTPathToDOS(t *testing.T) {
	t.Parallel()
	dm := map[string]string{`\Device\HarddiskVolume4`: "C:", `\Device\HarddiskVolume2`: "D:"}
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"volume 4 maps to C", `\Device\HarddiskVolume4\Windows\System32\cmd.exe`, `C:\Windows\System32\cmd.exe`},
		{"volume 2 maps to D", `\Device\HarddiskVolume2\data\x.exe`, `D:\data\x.exe`},
		{"unknown device unchanged", `\Device\HarddiskVolume9\x.exe`, `\Device\HarddiskVolume9\x.exe`},
		{"non-device path unchanged", `C:\already\dos.exe`, `C:\already\dos.exe`},
		{"device prefix without separator not matched", `\Device\HarddiskVolume4X\x`, `\Device\HarddiskVolume4X\x`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, ntPathToDOS(tc.in, dm))
		})
	}
}

// spec:windows-event-collection/windows-process-telemetry-via-etw/a-process-start-becomes-an-exec-envelope
// spec:windows-event-collection/windows-process-telemetry-via-etw/the-process-create-time-is-carried-as-the-pid-epoch
func TestExecEnvelope(t *testing.T) {
	t.Parallel()
	b, err := execEnvelope("evt-1", "host-1", 1700, execPayload{
		PID: 4332, PPID: 1000, Path: `C:\Windows\System32\cmd.exe`, Cwd: "", UID: 0, GID: 0, CreateTimeNs: 1_700_000_000_000_000_100,
	})
	require.NoError(t, err)
	var got struct {
		EventID     string          `json:"event_id"`
		HostID      string          `json:"host_id"`
		TimestampNs int64           `json:"timestamp_ns"`
		EventType   string          `json:"event_type"`
		Platform    string          `json:"platform"`
		Payload     json.RawMessage `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(b, &got))
	assert.Equal(t, "evt-1", got.EventID)
	assert.Equal(t, "host-1", got.HostID)
	assert.Equal(t, int64(1700), got.TimestampNs)
	assert.Equal(t, "exec", got.EventType)
	assert.Equal(t, "windows", got.Platform)

	var p struct {
		PID          int      `json:"pid"`
		PPID         int      `json:"ppid"`
		Path         string   `json:"path"`
		Args         []string `json:"args"`
		Cwd          string   `json:"cwd"`
		UID          int      `json:"uid"`
		GID          int      `json:"gid"`
		CreateTimeNs int64    `json:"create_time_ns"`
	}
	require.NoError(t, json.Unmarshal(got.Payload, &p))
	assert.Equal(t, 4332, p.PID)
	assert.Equal(t, 1000, p.PPID)
	assert.Equal(t, `C:\Windows\System32\cmd.exe`, p.Path)
	assert.NotNil(t, p.Args, "args must be a JSON array, never null")
	assert.Empty(t, p.Args)
	assert.Equal(t, int64(1_700_000_000_000_000_100), p.CreateTimeNs)
}

func TestExecEnvelope_ArgsAlwaysArray(t *testing.T) {
	t.Parallel()
	// A payload built with a nil Args must still serialize "args":[] (not null): the schema requires an array.
	b, err := execEnvelope("e", "h", 1, execPayload{PID: 1, Args: nil})
	require.NoError(t, err)
	assert.Contains(t, string(b), `"args":[]`)
	assert.NotContains(t, string(b), `"args":null`)
}

// spec:windows-event-collection/windows-process-telemetry-via-etw/a-process-stop-becomes-an-exit-envelope
func TestExitEnvelope(t *testing.T) {
	t.Parallel()
	b, err := exitEnvelope("evt-2", "host-1", 1800, exitPayload{PID: 4332, ExitCode: 0, CreateTimeNs: 1_700_000_000_000_000_100})
	require.NoError(t, err)
	assert.Contains(t, string(b), `"event_type":"exit"`)
	assert.Contains(t, string(b), `"platform":"windows"`)
	assert.Contains(t, string(b), `"exit_code":0`)
	assert.Contains(t, string(b), `"pid":4332`)
}
