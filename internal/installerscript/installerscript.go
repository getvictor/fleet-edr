// Package installerscript recognises a macOS package installer script, for the agent that attaches a package's signature to the
// script's exec and the server rule that trusts it (issue #1161). The two must agree exactly on which exec is an installer script
// and which argument names its package, or a signature could be attributed to one path while the alert names another, so both
// read this one definition rather than a copy each.
package installerscript

import "strings"

// ServicePath is Apple's PackageKit service that runs every package's preinstall and postinstall scripts. An installer script's
// exec has it as its parent.
const ServicePath = "/System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/XPCServices/" +
	"package_script_service.xpc/Contents/MacOS/package_script_service"

// Locate returns the installer script in an exec's argv and the argument that follows it: the package's path, per Apple's script
// interface ($1 is the package, then the target, the volume and its root). The script is argv[0] for a compiled script and argv[1]
// behind an interpreter, so it is found by the sandbox PackageKit runs it from rather than by position. Both are "" when argv
// holds no installer script with an argument after it.
func Locate(args []string) (script, pkg string) {
	for i := 1; i < len(args); i++ {
		if s := args[i-1]; strings.Contains(s, "/PKInstallSandbox.") && strings.Contains(s, "/Scripts/") {
			return s, args[i]
		}
	}
	return "", ""
}
