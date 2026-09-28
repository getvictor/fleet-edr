// Package enrich augments raw event JSON in the agent before it is queued and
// uploaded, with signatures the sandboxed system extension cannot read on a
// SIP-enabled host. The agent (an unsandboxed root daemon) can, and doing it
// here keeps signing evaluation off the Endpoint Security callback thread. It
// fills a btm_launch_item_add event's executable_code_signing from the
// registered executable (ADR-0008, 2026-05-29 amendment), and an installer
// script's exec with the signature of the package it came from (issue #1161).
//
// The JSON surgery is platform-neutral and fully unit-tested by injecting a
// fake Evaluator; the real evaluator (codesign.Evaluate) is darwin/cgo-only.
package enrich

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/fleetdm/edr/agent/codesign"
	"github.com/fleetdm/edr/agent/pkgsign"
	"github.com/fleetdm/edr/internal/installerscript"
)

// Evaluator computes the on-disk code signing of an executable. Production passes codesign.Evaluate; tests inject a
// deterministic fake. A false return means the executable could not be read (absent / unreadable), in which case enrichment
// leaves the field unset and the server rule skips.
type Evaluator func(path string) (*codesign.Result, bool)

// btmEventType is the only event enrich acts on. Kept in sync with the
// extension's serialized event_type and the server rule's EventTypes.
const btmEventType = "btm_launch_item_add"

// BtmExecutableSigning returns data with the btm_launch_item_add payload's
// executable_code_signing filled from the executable the item registers, or
// data unchanged when there is nothing to do. That executable is
// executable_path, or for a login item, which BTM reports with none, the
// helper app bundle the item names (issue #1167).
//
// It first resolves an item path that BTM reports relative to its app: an
// SMAppService item is named inside the registering app's bundle
// (Contents/Library/LoginItems/Helper.app), and app_url is that bundle. The
// resolved file:// URL replaces item_path, so the server sees where the item is.
//
// It is conservative and non-destructive:
//
//   - non-btm events, malformed JSON, and a missing payload are passed
//     through untouched, as is a registration with nothing to sign;
//   - an already-present, non-null executable_code_signing is left as-is
//     (the source, e.g. a synthetic test feed, stays authoritative);
//   - when eval reports the executable is unreadable, the field stays unset so
//     the rule treats it as "cannot classify" and skips.
//
// All envelope and payload fields the agent does not model are preserved by
// round-tripping through map[string]json.RawMessage.
func BtmExecutableSigning(data []byte, eval Evaluator) []byte {
	envelope, payload, ok := decodeEvent(data, btmEventType)
	if !ok {
		return data
	}
	itemURL := stringField(payload, "item_path")
	if resolved, ok := resolveItemURL(itemURL, stringField(payload, "app_url")); ok {
		itemURL = resolved
		data = encodeEvent(data, envelope, payload, "item_path", itemURL)
	}
	if hasField(payload, "executable_code_signing") {
		return data
	}
	path := registeredExecutable(payload, itemURL)
	if path == "" {
		return data
	}
	result, ok := eval(path)
	if !ok || result == nil {
		// Unreadable executable: leave executable_code_signing unset. The rule skips a registration it cannot classify.
		return data
	}
	return encodeEvent(data, envelope, payload, "executable_code_signing", result)
}

// btmLoginItem is the item type BTM reports with no executable_path: the item is a helper app bundle, which is what is signed.
const btmLoginItem = "login_item"

// resolveItemURL resolves an item URL that is relative to appURL, the registering app's bundle as a file:// URL (BTM reports it
// with a trailing slash). ok is false for an
// item URL that is already absolute, or when there is no app to resolve it against.
func resolveItemURL(itemURL, appURL string) (string, bool) {
	item, err := url.Parse(itemURL)
	if err != nil || itemURL == "" || item.IsAbs() {
		return "", false
	}
	app, err := url.Parse(appURL)
	if err != nil || app.Scheme != "file" {
		return "", false
	}
	// The app is a bundle, so a directory. Without the trailing slash, resolution would replace the bundle's name rather than
	// descend into it.
	if !strings.HasSuffix(app.Path, "/") {
		app.Path += "/"
		app.RawPath = ""
	}
	return app.ResolveReference(item).String(), true
}

// registeredExecutable is the path whose signature decides a registration: executable_path when BTM reports one, else the bundle a
// login item names, as a filesystem path. "" when there is neither.
func registeredExecutable(payload map[string]json.RawMessage, itemURL string) string {
	if path := stringField(payload, "executable_path"); path != "" {
		return path
	}
	if stringField(payload, "item_type") != btmLoginItem {
		return ""
	}
	item, err := url.Parse(itemURL)
	if err != nil || item.Scheme != "file" {
		return ""
	}
	return item.Path
}

// stringField is the payload's string value for key, or "" when it is absent, null, or not a string.
func stringField(payload map[string]json.RawMessage, key string) string {
	var v string
	if err := json.Unmarshal(payload[key], &v); err != nil {
		return ""
	}
	return v
}

// PackageEvaluator reads the signature of the package at pkgPath for the installer script at scriptPath. Production passes
// pkgsign.Evaluate; tests inject a fake. A false return means no trustworthy answer (unreadable, or changed during the install),
// and the event is left without a package signature.
type PackageEvaluator func(pkgPath, scriptPath string) (*pkgsign.Result, bool)

// ParentPath returns the executable path of the process with the given pid, as the agent's process table knows it.
type ParentPath func(pid int) (string, bool)

// PackageScriptSigning returns data with an installer script's exec carrying package_signing: the signature of the package the
// script belongs to. PackageKit runs a package's scripts under its own package_script_service, so the process chain names Apple
// and never the vendor; the package's path is the script's first argument (Apple's documented script interface), and its
// signature is what tells one vendor's installer from another, or from a planted one.
//
// Applied only when the exec's PARENT is package_script_service. The argument is anyone's to write, so without that check a
// script run from a shell could name a signed vendor package and borrow its signature. Everything else passes through
// unchanged, as does an exec that already carries package_signing or whose package cannot be read.
func PackageScriptSigning(data []byte, parentPath ParentPath, eval PackageEvaluator) []byte {
	envelope, payload, ok := decodeEvent(data, "exec")
	if !ok || hasField(payload, "package_signing") {
		return data
	}
	var exec struct {
		PPID int      `json:"ppid"`
		Args []string `json:"args"`
	}
	if err := json.Unmarshal(envelope["payload"], &exec); err != nil {
		return data
	}
	// The argument shape first: it is free, and it spares the parent lookup, which may ask the kernel, on every other exec.
	script, pkg := installerscript.Locate(exec.Args)
	if pkg == "" {
		return data
	}
	if parent, known := parentPath(exec.PPID); !known || parent != installerscript.ServicePath {
		return data
	}
	result, ok := eval(pkg, script)
	if !ok {
		return data
	}
	return encodeEvent(data, envelope, payload, "package_signing", result)
}

// decodeEvent parses an event envelope of wantType and its payload. ok is false for another type, malformed JSON, or a missing
// or null payload, all of which enrichment passes through untouched. Fields the agent does not model survive, because both
// levels round-trip through map[string]json.RawMessage.
func decodeEvent(data []byte, wantType string) (envelope, payload map[string]json.RawMessage, ok bool) {
	if err := json.Unmarshal(data, &envelope); err != nil || envelope == nil {
		// A JSON-null event unmarshals to a nil map, which the payload write below would panic on.
		return nil, nil, false
	}
	var eventType string
	if err := json.Unmarshal(envelope["event_type"], &eventType); err != nil || eventType != wantType {
		return nil, nil, false
	}
	if err := json.Unmarshal(envelope["payload"], &payload); err != nil || payload == nil {
		// A JSON-null payload unmarshals to a nil map, and writing a field into it would panic.
		return nil, nil, false
	}
	return envelope, payload, true
}

// hasField reports whether the payload already carries key with a non-null value, in which case the source (a synthetic test
// feed, say) stays authoritative. An explicit null counts as absent.
func hasField(payload map[string]json.RawMessage, key string) bool {
	v, present := payload[key]
	return present && !isJSONNull(v)
}

// encodeEvent writes value into the payload under key and re-encodes the event, returning the original data if any step fails.
func encodeEvent(original []byte, envelope, payload map[string]json.RawMessage, key string, value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		return original
	}
	payload[key] = raw
	newPayload, err := json.Marshal(payload)
	if err != nil {
		return original
	}
	envelope["payload"] = newPayload
	out, err := json.Marshal(envelope)
	if err != nil {
		return original
	}
	return out
}

// isJSONNull reports whether raw is the JSON literal null (ignoring surrounding whitespace). An explicit null is treated
// the same as an absent field: enrich fills it.
func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}
