package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/fleetdm/edr/test/fakeagent"
)

// pidVersionStamper reproduces the kernel's pidversion counter over replayed demo events.
//
// pidversion is what the server correlates a network flow, and an alert chain's timeline scope, back to an exact process
// generation: the pair (pid, pidversion) survives pid reuse where a bare pid does not. Real agents read it from the audit token.
// The demo corpus is captured wire data that predates the field, so every replayed process landed with a NULL pidversion, and the
// alert timeline could never narrow to a chain: it fell back to the whole host on every demo alert.
//
// The semantics here are measured off a live macOS host rather than assumed. On agent v0.5.0-rc.2, events 13940..13952 ran
// consecutively with no gaps across four different pids, one increment per fork and one per exec:
//
//	13946 fork  child=5740        13947 fork  child=5741
//	13948 exec  pid=5741          13949 exec  pid=5741   (re-exec bumps again)
//	13950 fork  child=5742        13951 exec  pid=5742
//
// So it is a SYSTEM-WIDE monotonic counter, not a per-pid one, incremented on process creation and on each exec. A flow carries
// whatever generation its source pid is currently on.
type pidVersionStamper struct {
	// next is the system-wide counter. It only ever moves forward, across every host stream this stamper is used for.
	next int64
	// current maps a pid to the generation its most recent fork or exec assigned, which is what a flow from that pid carries.
	current map[int]int64
}

// pidVersionSeed is where the synthetic counter starts. A non-zero, non-trivial base keeps demo values from reading like row
// indices, and matches the order of magnitude a host reaches within an hour of boot.
const pidVersionSeed = 10000

func newPIDVersionStamper() *pidVersionStamper {
	return &pidVersionStamper{next: pidVersionSeed, current: map[int]int64{}}
}

// stamp writes a pidversion into every envelope that carries one, in place.
//
// Order matters and file order will not do: the scrubbed captures are NOT stored time-sorted (the same reason
// pickAttackAnchorPID selects on TimestampNs rather than taking the last line), so stamping in slice order would hand a process
// a generation minted before its own fork. Envelopes are walked in timestamp order and the results written back to their
// original positions, leaving the caller's slice ordering untouched.
func (st *pidVersionStamper) stamp(envs []fakeagent.Envelope) error {
	order := make([]int, len(envs))
	for i := range order {
		order[i] = i
	}
	// Stable on ties so two events sharing a timestamp keep their captured relative order, which is the only signal left about
	// which happened first.
	sort.SliceStable(order, func(a, b int) bool { return envs[order[a]].TimestampNs < envs[order[b]].TimestampNs })

	for _, i := range order {
		field, ok := pidVersionFieldFor(envs[i].EventType)
		if !ok {
			continue
		}
		if err := st.stampOne(&envs[i], field); err != nil {
			return fmt.Errorf("stamp pidversion on %s %s: %w", envs[i].EventType, envs[i].EventID, err)
		}
	}
	return nil
}

// pidVersionKind says which pid field an event type's generation is keyed on, and whether the event mints a new generation or
// merely reports the one its process is already on.
type pidVersionKind struct {
	// pidField is the payload key naming the process this event's pidversion belongs to. fork reports the CHILD's generation.
	pidField string
	// mints is true when the event advances the counter (a process was created or exec'd) and false when it only observes.
	mints bool
}

// pidVersionFieldFor returns the stamping rule for an event type, or false for the event types that carry no pidversion at all.
// The four that do are exactly the four the wire schema declares it on (schema/events.json).
func pidVersionFieldFor(eventType string) (pidVersionKind, bool) {
	switch eventType {
	case "fork":
		return pidVersionKind{pidField: "child_pid", mints: true}, true
	case "exec":
		return pidVersionKind{pidField: "pid", mints: true}, true
	case "network_connect", "dns_query":
		return pidVersionKind{pidField: "pid", mints: false}, true
	default:
		return pidVersionKind{}, false
	}
}

func (st *pidVersionStamper) stampOne(env *fakeagent.Envelope, kind pidVersionKind) error {
	payload, err := decodePayload(env.Payload)
	if err != nil {
		return err
	}
	pid, ok := intFrom(payload[kind.pidField])
	if !ok {
		// No pid to key on. A flow whose source the capture never identified genuinely has no generation, and inventing one
		// would correlate it to whichever process later reuses that pid.
		return nil
	}
	var version int64
	if kind.mints {
		st.next++
		version = st.next
		st.current[pid] = version
	} else {
		version, ok = st.current[pid]
		if !ok {
			// A flow from a process whose fork/exec is not in this capture. Real agents omit the field in exactly this case
			// ("Absent ... when the flow carried no usable audit token"), so leaving it absent is the faithful answer.
			return nil
		}
	}
	payload["pidversion"] = version
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("re-encode payload: %w", err)
	}
	env.Payload = raw
	return nil
}

// decodePayload decodes a payload preserving number formatting.
//
// UseNumber is load-bearing: the default decode turns every JSON number into a float64, and re-encoding a nanosecond timestamp
// or a large hash-like integer from a float64 loses precision or emits scientific notation, silently corrupting fields this
// function has no business touching.
func decodePayload(raw json.RawMessage) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var payload map[string]any
	if err := dec.Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	return payload, nil
}

// intFrom reads a pid out of a decoded payload. Values arrive as json.Number because of decodePayload's UseNumber.
func intFrom(v any) (int, bool) {
	num, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := num.Int64()
	if err != nil {
		return 0, false
	}
	return int(parsed), true
}
