package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"slices"

	"github.com/fleetdm/edr/server/rules/api"
)

// untrustedRegistration decodes a Background Task Management registration of one of itemTypes and reports whether it is one a
// persistence rule judges: not MDM-managed, with a readable signature on the executable it registers, and that executable not an
// Apple platform binary. Three rules make this decision (privilege_launchd_plist_write for daemons, persistence_launchagent for
// agents, persistence_login_item for login items and apps), and differ only in what they call the item and how an operator waives
// it. For a login item or an app, which BTM reports with no executable, the signature is the app bundle's.
//
// The decision rides the REGISTERED EXECUTABLE's signature, not the registration's instigator, which for a `launchctl` or
// SMAppService registration is Apple's smd and so cannot discriminate. A registration with no readable signature is skipped to stay
// high-precision.
func untrustedRegistration(evt api.Event, itemTypes ...string) (btmLaunchItemAddPayload, bool) {
	var p btmLaunchItemAddPayload
	if evt.EventType != "btm_launch_item_add" {
		return p, false
	}
	if err := json.Unmarshal(evt.Payload, &p); err != nil {
		// A malformed BTM event is noise from a misbehaving extension build, not a detection signal.
		return p, false
	}
	if !slices.Contains(itemTypes, p.ItemType) || p.Managed || p.ExecutableCodeSigning == nil || p.ExecutableCodeSigning.IsPlatformBinary {
		return p, false
	}
	return p, true
}

// pathSubject builds the dedup subject for a finding about a file rather than a process run: "<kind>:<path>" when that fits
// alerts.subject, and a fixed-length SHA-256 of the path when it would not. The hash is stable per path, so repeats of one item
// still collapse while distinct items stay distinct. The BTM persistence rules name their item by it, and the installer rule its
// package.
func pathSubject(kind, itemPath string) string {
	subject := kind + ":" + itemPath
	if len(subject) <= subjectColumnLimit {
		return subject
	}
	sum := sha256.Sum256([]byte(itemPath))
	return kind + ":sha256:" + hex.EncodeToString(sum[:])
}

// btmItemPath is a registration's item path (a launchd item's plist, a login item's helper bundle) as a filesystem path. The
// extension reports the item as a `file://` URL, and an operator writes a path glob as a path, so matching the URL form would leave
// every path exclusion matching nothing. Anything that is not a file URL is returned unchanged.
func btmItemPath(itemPath string) string {
	u, err := url.Parse(itemPath)
	if err != nil || u.Scheme != "file" {
		return itemPath
	}
	return u.Path
}

// signatureExcluded reports whether an exclusion saved for ruleID names a binary by its signature: its team, or its signing
// identifier QUALIFIED by that team (or by `platform`). Never the bare identifier (issue #1024): an ad-hoc binary can claim any
// vendor's identifier, so the bare form let a planted binary inherit that vendor's exclusion. A binary with no team and no platform
// flag composes to "" and matches no signing_id exclusion at all.
func signatureExcluded(res api.ExclusionResolver, ruleID string, cs codeSigningJSON, hostID string) bool {
	if cs.TeamID != "" && res.Excluded(ruleID, api.ExclusionMatchTeamID, cs.TeamID, hostID) {
		return true
	}
	qualified := api.QualifiedSigningID(cs.TeamID, cs.SigningID, cs.IsPlatformBinary)
	return qualified != "" && res.Excluded(ruleID, api.ExclusionMatchSigningID, qualified, hostID)
}
