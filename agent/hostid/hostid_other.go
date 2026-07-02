//go:build !darwin && !windows

package hostid

import (
	"context"
	"errors"
)

// Get returns an error on platforms without a host-identity source yet (Linux and the like). This matches the pre-split runtime
// behavior on non-macOS: the agent falls back to the EDR_HOST_ID override, which the enrollment flow requires on these platforms. A
// native source (for example the systemd machine-id) can replace this when a Linux agent lands.
func Get(_ context.Context) (string, error) {
	return "", errors.New("hostid: no host-identity source on this platform; set EDR_HOST_ID")
}
