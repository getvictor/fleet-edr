package engine

import (
	"bytes"
	"encoding/json"

	"github.com/fleetdm/edr/server/detection/api"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
)

// snapshotMarker is the field-name fast-path used to short-circuit the snapshot-exec filter. The vast majority of exec events don't
// carry the snapshot field at all, so we skip the JSON decode for them. We gate on just the field name (not the value) so the filter
// stays robust to encoder formatting differences (whitespace around the colon, key reordering, pretty-printing) that would silently
// break a byte-exact `"snapshot":true` gate. The unmarshal probe below is JSON-spec aware and is the source of truth on the boolean
// value.
var snapshotMarker = []byte(`"snapshot"`)

type snapshotProbe struct {
	Snapshot bool `json:"snapshot"`
}

// filterSnapshotEvents returns the subset of events that detection rules should evaluate. Two kinds of "plumbing" events are dropped
// here so each rule doesn't have to remember:
//
//  1. exec events with snapshot=true (issue #11): synthetic events emitted by the extension's startup baseline pass. They describe
//     pre-existing state, not new attacker activity.
//  2. snapshot_heartbeat events (issue #173): periodic liveness pings from the agent that bump processes.last_seen_ns. Pure liveness
//     plumbing; nothing for rules to evaluate.
//
// The common case (no plumbing event in the batch) returns the input slice verbatim, so Engine.Evaluate pays zero per-batch
// allocation in steady state. Only the first dropped event triggers a copy.
func filterSnapshotEvents(events []api.Event) []api.Event {
	for i, evt := range events {
		if !isPlumbingEvent(evt) {
			continue
		}
		// First plumbing event found at index i: copy the prefix that already passed and continue scanning the suffix. Capacity
		// sized for "everything but this one event": a reasonable guess that avoids a second alloc when only one plumbing event is
		// present, which is the typical extension-startup shape.
		out := make([]api.Event, 0, len(events)-1)
		out = append(out, events[:i]...)
		for _, evt := range events[i+1:] {
			if isPlumbingEvent(evt) {
				continue
			}
			out = append(out, evt)
		}
		return out
	}
	return events
}

// platformScopedEvents returns the subset of events whose platform is in the rule's target set (ADR-0018). An event carrying no
// platform is treated as darwin, the legacy-agent default, so a pre-platform-contract event still reaches the macOS rules. The common
// single-platform batch returns the input slice verbatim (every event matches or none do), so a homogeneous fleet pays no per-rule
// allocation; a mixed-platform batch is copied down to the matching subset.
func platformScopedEvents(platforms []rulesapi.Platform, events []api.Event) []api.Event {
	set := make(map[string]struct{}, len(platforms))
	for _, p := range platforms {
		set[string(p)] = struct{}{}
	}
	firstMiss := -1
	for i := range events {
		if _, ok := set[api.NormalizePlatform(events[i].Platform)]; !ok {
			firstMiss = i
			break
		}
	}
	if firstMiss == -1 {
		return events
	}
	out := make([]api.Event, 0, len(events)-1)
	out = append(out, events[:firstMiss]...)
	for i := firstMiss + 1; i < len(events); i++ {
		if _, ok := set[api.NormalizePlatform(events[i].Platform)]; ok {
			out = append(out, events[i])
		}
	}
	return out
}

// isPlumbingEvent returns true for events that flow through ingest + graph but should not reach rule evaluation. Centralised here
// so a new plumbing event type only needs one switch arm rather than a guard in every rule.
func isPlumbingEvent(evt api.Event) bool {
	switch evt.EventType {
	case "snapshot_heartbeat":
		return true
	case "exec":
		return isSnapshotExec(evt)
	}
	return false
}

func isSnapshotExec(evt api.Event) bool {
	if evt.EventType != "exec" {
		return false
	}
	if !bytes.Contains(evt.Payload, snapshotMarker) {
		return false
	}
	var probe snapshotProbe
	if err := json.Unmarshal(evt.Payload, &probe); err != nil {
		return false
	}
	return probe.Snapshot
}
