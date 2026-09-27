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
	"strings"

	"github.com/fleetdm/edr/agent/codesign"
	"github.com/fleetdm/edr/agent/pkgsign"
)

// Evaluator computes the on-disk code signing of an executable. Production passes codesign.Evaluate; tests inject a
// deterministic fake. A false return means the executable could not be read (absent / unreadable), in which case enrichment
// leaves the field unset and the server rule skips.
type Evaluator func(path string) (*codesign.Result, bool)

// btmEventType is the only event enrich acts on. Kept in sync with the
// extension's serialized event_type and the server rule's EventTypes.
const btmEventType = "btm_launch_item_add"

// BtmExecutableSigning returns data with the btm_launch_item_add payload's
// executable_code_signing filled from eval(executable_path), or data unchanged
// when there is nothing to do. It is conservative and non-destructive:
//
//   - non-btm events, malformed JSON, a missing payload, or a missing
//     executable_path are passed through untouched;
//   - an already-present, non-null executable_code_signing is left as-is
//     (the source, e.g. a synthetic test feed, stays authoritative);
//   - when eval reports the executable is unreadable, the field stays unset so
//     the rule treats it as "cannot classify" and skips.
//
// All envelope and payload fields the agent does not model are preserved by
// round-tripping through map[string]json.RawMessage.
func BtmExecutableSigning(data []byte, eval Evaluator) []byte {
	envelope, payload, ok := decodeEvent(data, btmEventType)
	if !ok || hasField(payload, "executable_code_signing") {
		return data
	}
	var executablePath string
	if err := json.Unmarshal(payload["executable_path"], &executablePath); err != nil || executablePath == "" {
		return data
	}
	result, ok := eval(executablePath)
	if !ok || result == nil {
		// Unreadable executable: leave executable_code_signing unset. The rule skips a registration it cannot classify.
		return data
	}
	return encodeEvent(data, envelope, payload, "executable_code_signing", result)
}

// PackageEvaluator reads the signature of the package at pkgPath for the installer script at scriptPath. Production passes
// pkgsign.Evaluate; tests inject a fake. A false return means no trustworthy answer (unreadable, or changed during the install),
// and the event is left without a package signature.
type PackageEvaluator func(pkgPath, scriptPath string) (*pkgsign.Result, bool)

// ParentPath returns the executable path of the process with the given pid, as the agent's process table knows it.
type ParentPath func(pid int) (string, bool)

// PackageScriptServicePath is Apple's PackageKit service that runs every package's preinstall and postinstall scripts.
const PackageScriptServicePath = "/System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/XPCServices/" +
	"package_script_service.xpc/Contents/MacOS/package_script_service"

// installerSandboxScripts is the part of an installer script's path that PackageKit's sandbox always carries, as in
// /tmp/PKInstallSandbox.iJ0s6V/Scripts/com.example.pkg.gjgthW/postinstall.
const installerSandboxScripts = "/Scripts/"

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
	script, pkg := installerScript(exec.Args)
	if pkg == "" {
		return data
	}
	if parent, known := parentPath(exec.PPID); !known || parent != PackageScriptServicePath {
		return data
	}
	result, ok := eval(pkg, script)
	if !ok {
		return data
	}
	return encodeEvent(data, envelope, payload, "package_signing", result)
}

// installerScript returns the installer script in args and the argument that follows it: the package path, per Apple's script
// interface ($1 is the package, then the target, the volume and its root). The script is argv[0] for a compiled script and
// argv[1] behind an interpreter, so it is found by its sandbox path rather than by position. Both are "" when there is none.
func installerScript(args []string) (script, pkg string) {
	for i := 1; i < len(args); i++ {
		if s := args[i-1]; strings.Contains(s, "/PKInstallSandbox.") && strings.Contains(s, installerSandboxScripts) {
			return s, args[i]
		}
	}
	return "", ""
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
