//go:build darwin

package hostid

// This file is the macOS host-identity source: it derives the hardware UUID (IOPlatformUUID) via ioreg. Other platforms provide their
// own Get in hostid_windows.go and hostid_other.go. The package doc lives in doc.go so it is present on every build.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
)

// ioregPath is the absolute path to /usr/sbin/ioreg; declared as a var so tests
// can override it.
var ioregPath = "/usr/sbin/ioreg"

// uuidRegexp matches `"IOPlatformUUID" = "<uuid>"` in ioreg output.
var uuidRegexp = regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([^"]+)"`)

// Get reads the macOS IOPlatformUUID and returns it as a string. It shells out to ioreg which is always present on macOS. On non-macOS
// platforms, or if the command fails, an error is returned.
func Get(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, ioregPath, "-rd1", "-c", "IOPlatformExpertDevice")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("run ioreg: %w (stderr: %s)", err, stderr.String())
	}
	return parseIORegOutput(stdout.Bytes())
}

// parseIORegOutput extracts the IOPlatformUUID from ioreg's output. Kept
// separate so unit tests can exercise it with a fixture.
func parseIORegOutput(out []byte) (string, error) {
	m := uuidRegexp.FindSubmatch(out)
	if m == nil {
		return "", errors.New("IOPlatformUUID not found in ioreg output")
	}
	return string(m[1]), nil
}
