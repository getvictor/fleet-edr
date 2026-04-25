package detection

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/fleetdm/edr/server/store"
)

// MetricsRecorder is the Phase 4 counter interface. Nil is fine; metrics are optional.
type MetricsRecorder interface {
	AlertCreated(ctx context.Context, ruleID, severity string)
}

// Engine manages a set of rules and evaluates them against event batches.
type Engine struct {
	rules   []Rule
	store   *store.Store
	logger  *slog.Logger
	metrics MetricsRecorder
}

// NewEngine creates a detection engine backed by the given store.
func NewEngine(s *store.Store, logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{store: s, logger: logger}
}

// SetMetrics installs the OTel counter hook. Safe to call after NewEngine.
func (e *Engine) SetMetrics(m MetricsRecorder) { e.metrics = m }

// Register adds a detection rule to the engine.
func (e *Engine) Register(r Rule) {
	e.rules = append(e.rules, r)
}

// RuleMetadata describes a registered rule for callers outside the engine
// (e.g. the Navigator-export handler in server/admin). Kept intentionally
// minimal — ID + Techniques — because any more structure pulls detection
// concerns into the admin surface.
type RuleMetadata struct {
	ID         string
	Techniques []string
}

// Catalog returns the metadata for every registered rule. Order matches
// registration order so callers can render deterministic output.
func (e *Engine) Catalog() []RuleMetadata {
	out := make([]RuleMetadata, 0, len(e.rules))
	for _, r := range e.rules {
		out = append(out, RuleMetadata{ID: r.ID(), Techniques: r.Techniques()})
	}
	return out
}

// Evaluate runs all registered rules against the event batch.
// Findings are persisted as alerts. Rule evaluation failures are logged and skipped,
// but alert persistence failures are returned so the caller can retry the batch.
//
// Snapshot exec events (issue #11: ESF baseline enumeration) are filtered
// out before rule evaluation. Those events describe processes that existed
// before the extension subscribed to ESF — they're stitched into the
// process tree by graph.Builder.insertExecWithoutFork so an analyst can
// see Safari, Slack, Finder, etc., but they represent historical state,
// not new attacker activity. Letting rules see them would generate false
// positives every time the extension restarts (e.g. dyld_insert firing
// on a Safari debug-build with DYLD_INSERT_LIBRARIES set).
func (e *Engine) Evaluate(ctx context.Context, events []store.Event) error {
	live := filterSnapshotEvents(events)
	for _, rule := range e.rules {
		findings, err := rule.Evaluate(ctx, live, e.store)
		if err != nil {
			e.logger.WarnContext(ctx, "detection rule evaluation failed", "rule", rule.ID(), "err", err)
			continue
		}
		techniques := rule.Techniques()
		for _, f := range findings {
			if err := e.persistFinding(ctx, f, techniques); err != nil {
				return err
			}
		}
	}
	return nil
}

// snapshotMarker is the field-name fast-path used to short-circuit the
// snapshot-exec filter. The vast majority of exec events don't carry the
// snapshot field at all, so we skip the JSON decode for them. We gate on
// just the field name (not the value) so the filter stays robust to
// encoder formatting differences — whitespace around the colon, key
// reordering, pretty-printing, all of which would silently break a
// byte-exact `"snapshot":true` gate and let snapshot events back into
// rule evaluation. The unmarshal probe below is JSON-spec aware and is
// the source of truth on the boolean value.
var snapshotMarker = []byte(`"snapshot"`)

type snapshotProbe struct {
	Snapshot bool `json:"snapshot"`
}

// filterSnapshotEvents returns the subset of events that detection rules
// should evaluate. Currently the only filter is for `snapshot=true` exec
// events (issue #11); future filters can stack here without rules
// needing to repeat the check.
//
// The common case — no snapshot exec in the batch — returns the input
// slice verbatim, so Engine.Evaluate pays zero per-batch allocation in
// steady state. Only the first dropped event triggers a copy.
func filterSnapshotEvents(events []store.Event) []store.Event {
	for i, evt := range events {
		if !isSnapshotExec(evt) {
			continue
		}
		// First snapshot found at index i: copy the prefix that already
		// passed and continue scanning the suffix. Capacity sized for
		// "everything but this one event" — a reasonable guess that
		// avoids a second alloc when only one snapshot is present, which
		// is the typical extension-startup shape.
		out := make([]store.Event, 0, len(events)-1)
		out = append(out, events[:i]...)
		for _, evt := range events[i+1:] {
			if isSnapshotExec(evt) {
				continue
			}
			out = append(out, evt)
		}
		return out
	}
	return events
}

func isSnapshotExec(evt store.Event) bool {
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

// persistFinding inserts a single finding as an alert, stamping it with the
// rule's ATT&CK techniques and emitting the new-alert log line + metric only
// when the insert wasn't deduped away. Extracted from Evaluate so that method
// stays under the project cognitive-complexity cap.
func (e *Engine) persistFinding(ctx context.Context, f Finding, techniques []string) error {
	// Stamp findings with the rule's ATT&CK techniques so the historical
	// alert keeps the mapping it fired under even if the rule metadata is
	// later refined.
	if f.Techniques == nil {
		f.Techniques = techniques
	}
	_, created, err := e.store.InsertAlert(ctx, store.Alert{
		HostID:      f.HostID,
		RuleID:      f.RuleID,
		Severity:    f.Severity,
		Title:       f.Title,
		Description: f.Description,
		ProcessID:   f.ProcessID,
		Techniques:  f.Techniques,
	}, f.EventIDs)
	if err != nil {
		return fmt.Errorf("persist detection alert for rule %s on host %s: %w", f.RuleID, f.HostID, err)
	}
	if !created {
		// Dedup-skip path (same rule + process + host) — evaluator noise,
		// not a new finding. Operators care about the new-alert rate.
		return nil
	}
	e.logger.InfoContext(ctx, "detection alert created",
		"rule", f.RuleID, "host", f.HostID, "severity", f.Severity, "title", f.Title)
	if e.metrics != nil {
		e.metrics.AlertCreated(ctx, f.RuleID, f.Severity)
	}
	return nil
}
