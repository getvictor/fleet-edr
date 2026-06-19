package receiver

import (
	"context"
	"os/exec"
	"strings"
)

// neExtensionBundleID is the network extension's bundle identifier as systemextensionsctl reports it (NOT the app-group Mach
// service name the agent connects to). A staged upgrade leaves the previous version of this bundle waiting to uninstall on
// reboot while the new version is active, which strands the NE's Mach service registration on the dead version (#399).
const neExtensionBundleID = "com.fleetdm.edr.networkextension"

// uninstallOnRebootMarker is the state phrase systemextensionsctl prints for a version macOS will remove on the next reboot.
const uninstallOnRebootMarker = "waiting to uninstall on reboot"

// NEUpgradePending reports whether the OS has a previous network-extension version staged for removal on reboot, the condition
// that strands the NE's Mach service registration on the dead version until reboot (#399). Best-effort: any error running
// systemextensionsctl (including on non-darwin, where the binary is absent) returns false, so the agent falls back to the
// generic connect-failure warning rather than a misleading reboot hint. Wired as the network-extension Loop's UpgradeProbe;
// the ESF loop does not use it.
func NEUpgradePending(ctx context.Context) bool {
	out, err := exec.CommandContext(ctx, "systemextensionsctl", "list").CombinedOutput()
	if err != nil {
		return false
	}
	return parseNEUpgradePending(string(out), neExtensionBundleID)
}

// parseNEUpgradePending is the pure core: true when any single line names the network-extension bundle AND carries the
// waiting-to-uninstall-on-reboot marker. Per-line matching on those two stable tokens isolates the old, terminated version
// (which carries the marker) from the new, active version (same bundle id, no marker) and stays robust to the surrounding
// columns (team id, version, display name, enabled/active flags) that vary across macOS versions and install states.
func parseNEUpgradePending(systemextensionsctlOutput, bundleID string) bool {
	for line := range strings.SplitSeq(systemextensionsctlOutput, "\n") {
		if strings.Contains(line, bundleID) && strings.Contains(line, uninstallOnRebootMarker) {
			return true
		}
	}
	return false
}
