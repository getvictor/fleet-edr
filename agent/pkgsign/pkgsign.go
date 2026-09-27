// Package pkgsign reads the signature of a macOS installer package (a .pkg).
//
// It exists for installer scripts. PackageKit runs a package's preinstall and postinstall under Apple's own
// package_script_service, so the process chain names Apple's installer, never the vendor whose package it is. The package's own
// path is handed to each script as its first argument, and its signature is what tells a vendor's installer from a planted one
// (issue #1161).
//
// There is no public Security API for a flat package's signature: SecStaticCode reads code, not packages. So the darwin build
// runs `pkgutil --check-signature`, which answers locally from the package and its stapled ticket. It is called off the Endpoint
// Security callback thread, and only for an installer script, which is rare. Off darwin it is a stub.
package pkgsign

import (
	"regexp"
	"strings"
)

// Result is a package's signature in the wire shape of schema/events.json's `package_signing` definition.
type Result struct {
	// Signed is true when the package carries a signature that chains to a certificate macOS trusts. An untrusted or absent
	// signature is false.
	Signed bool `json:"signed"`
	// Notarized is true when Apple's notary service has accepted the package. Context, not trust: Apple has notarized malware.
	Notarized bool `json:"notarized"`
	// TeamID is the Developer ID team that signed the package, or "" when there is none (unsigned, or signed by Apple itself).
	TeamID string `json:"team_id"`
}

// teamSuffix is the parenthesised ten-character team identifier that ends a Developer ID certificate's common name, as in
// "Developer ID Installer: Example Corp (ABCDE12345)".
var teamSuffix = regexp.MustCompile(`\(([A-Z0-9]{10})\)\s*$`)

// Parse reads `pkgutil --check-signature` output. ok is false when the output has no Status line, which means pkgutil could
// not read the package at all: that is "cannot classify", not "unsigned".
func Parse(output string) (res Result, ok bool) {
	for line := range strings.Lines(output) {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Status:"):
			ok = true
			status := strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
			res.Signed = strings.HasPrefix(status, "signed") && !strings.Contains(status, "untrusted")
		case line == "Notarization: trusted by the Apple notary service":
			res.Notarized = true
		case strings.HasPrefix(line, "1. "):
			// The certificate chain's first entry is the leaf that signed the package; the rest are intermediates and Apple's root,
			// which carry no team.
			if m := teamSuffix.FindStringSubmatch(line); m != nil {
				res.TeamID = m[1]
			}
		}
	}
	if !res.Signed {
		// A team named by an untrusted certificate is whatever the signer typed, so it is not reported.
		res.TeamID = ""
	}
	return res, ok
}
