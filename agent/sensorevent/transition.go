// Package sensorevent turns capture-provider liveness reports into durable events on the server.
//
// Agent health (issue #649) is LEVEL state: it says what is true now. That is the right shape for a dashboard and the wrong
// shape for evidence. Once the self-heal (issue #632) restores a provider that someone switched off, health reads healthy
// again and nothing anywhere records that it ever stopped. Disabling security tooling is MITRE T1562.001, so an analyst
// asking "was this host's sensor tampered with?" a day later needs an answer that outlives the repair (issue #684).
//
// The emitter is deliberately ignorant of remediation. Whether a stop was repaired is not known when the stop happens, so
// instead of modelling an outcome it cannot populate, it emits the transitions and lets the PAIR carry the story: stopped
// at T, running at T+36s is a repaired tamper; a stopped with no running after it is an unrepaired one. That keeps this
// package decoupled from the self-heal controller entirely.
package sensorevent

import (
	"context"
	"log/slog"
	"maps"
	"sort"
)

// EventType is the wire event_type emitted for a provider transition. Registered in schema/events.json; the server does not
// validate against a closed set, so this needs no server change to be accepted and stored.
const EventType = "sensor_provider_transition"

// Provider states as reported by the extension. A provider the operator deliberately disabled is ABSENT from the report
// rather than carrying a state (issue #649), which is what keeps a supported opt-out from looking like a fault.
const (
	StateRunning = "running"
	StateStopped = "stopped"
)

// Emitter enqueues one event. Matches the agent's enqueue seam so this package does not depend on the queue implementation.
type Emitter func(ctx context.Context, eventType string, payload map[string]any) error

// Transitions turns consecutive liveness reports into events.
//
// Concurrency: Observe is called from the receiver loop's event callback, which is single-threaded per loop, so the
// previous-report state needs no lock. That is asserted by the one caller rather than defended against.
type Transitions struct {
	emit   Emitter
	logger *slog.Logger
	// last is the previous report's provider-to-state map. Nil until the first report: the first report establishes a
	// baseline rather than emitting, because an agent restart re-learns state it has not observed changing and emitting
	// there would manufacture a transition out of a reconnect.
	last map[string]string
}

func New(emit Emitter, logger *slog.Logger) *Transitions {
	if logger == nil {
		logger = slog.Default()
	}
	return &Transitions{emit: emit, logger: logger}
}

// Observe diffs a liveness report against the previous one and emits an event per real transition. reasons carries the raw
// platform stop reason per stopped provider and may be nil (an extension too old to send it).
//
// Returns the providers it emitted for, so a caller or test can assert the decision without reaching into private state.
func (t *Transitions) Observe(ctx context.Context, providers map[string]string, reasons map[string]int) []string {
	if t.emit == nil {
		return nil
	}
	// First report of the process: establish a baseline. Emitting here would turn every agent restart and every XPC
	// reconnect into a fabricated transition, which is exactly the noise that makes a tamper signal unusable.
	if t.last == nil {
		t.last = copyStates(providers)
		return nil
	}

	var emitted []string
	for provider, state := range providers {
		if state != StateRunning && state != StateStopped {
			// An unrecognised state from a newer extension. The baseline is deliberately LEFT ALONE rather than advanced to
			// it: "we do not know what this means" is not evidence the provider changed, and recording it would make the
			// next recognised state differ from the baseline and emit a transition that never happened. Holding the last
			// known state means a later running or stopped report is still judged against the last thing we understood.
			continue
		}
		if t.last[provider] == state {
			continue
		}
		if err := t.emitTransition(ctx, provider, state, reasons); err != nil {
			// Do NOT advance `last` for this provider: leaving it stale means the next report retries the same transition
			// rather than silently swallowing the one piece of evidence this package exists to produce.
			t.logger.WarnContext(ctx, "could not record capture provider transition; will retry on the next report",
				"provider", provider, "state", state, "err", err)
			continue
		}
		t.last[provider] = state
		emitted = append(emitted, provider)
	}
	// A provider that vanished from the report was deliberately disabled (issue #649 reports a supported opt-out as
	// absence). That is not a fault and must not emit, but the baseline has to drop it so a later re-appearance reads as a
	// transition rather than as no change.
	for provider := range t.last {
		if _, present := providers[provider]; !present {
			delete(t.last, provider)
		}
	}
	sort.Strings(emitted)
	return emitted
}

func (t *Transitions) emitTransition(ctx context.Context, provider, state string, reasons map[string]int) error {
	payload := map[string]any{"provider": provider, "state": state}
	// The reason is meaningful only for a stop, and only when the extension sent one.
	if state == StateStopped {
		if reason, ok := reasons[provider]; ok {
			payload["stop_reason"] = reason
		}
	}
	if err := t.emit(ctx, EventType, payload); err != nil {
		return err
	}
	t.logger.InfoContext(ctx, "recorded capture provider transition",
		"provider", provider, "state", state, "stop_reason", payload["stop_reason"])
	return nil
}

func copyStates(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	maps.Copy(out, in)
	return out
}
