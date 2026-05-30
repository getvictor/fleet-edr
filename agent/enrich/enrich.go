// Package enrich augments raw event JSON in the agent before it is queued and
// uploaded. Today it has a single job: fill a btm_launch_item_add event's
// executable_code_signing from the on-disk signing of the registered
// executable, which the sandboxed system extension cannot read on a
// SIP-enabled host (ADR-0008, 2026-05-29 amendment). The agent — an
// unsandboxed root daemon — can, and doing it here keeps signing evaluation
// off the Endpoint Security callback thread.
//
// The JSON surgery is platform-neutral and fully unit-tested by injecting a
// fake Evaluator; the real evaluator (codesign.Evaluate) is darwin/cgo-only.
package enrich

import (
	"bytes"
	"encoding/json"

	"github.com/fleetdm/edr/agent/codesign"
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
//     (the source — e.g. a synthetic test feed — stays authoritative);
//   - when eval reports the executable is unreadable, the field stays unset so
//     the rule treats it as "cannot classify" and skips.
//
// All envelope and payload fields the agent does not model are preserved by
// round-tripping through map[string]json.RawMessage.
func BtmExecutableSigning(data []byte, eval Evaluator) []byte {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(data, &envelope); err != nil {
		return data
	}

	var eventType string
	if err := json.Unmarshal(envelope["event_type"], &eventType); err != nil || eventType != btmEventType {
		return data
	}

	payloadRaw, ok := envelope["payload"]
	if !ok {
		return data
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		return data
	}
	// A JSON-null payload unmarshals to a nil map; writing executable_code_signing into it below would panic. A
	// btm_launch_item_add with a null payload is degenerate, so pass it through untouched.
	if payload == nil {
		return data
	}

	// Already provided (non-null) -> trust the source, do nothing.
	if cs, present := payload["executable_code_signing"]; present && !isJSONNull(cs) {
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

	csBytes, err := json.Marshal(result)
	if err != nil {
		return data
	}
	payload["executable_code_signing"] = csBytes

	newPayload, err := json.Marshal(payload)
	if err != nil {
		return data
	}
	envelope["payload"] = newPayload

	out, err := json.Marshal(envelope)
	if err != nil {
		return data
	}
	return out
}

// isJSONNull reports whether raw is the JSON literal null (ignoring surrounding whitespace). An explicit null is treated
// the same as an absent field: enrich fills it.
func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}
