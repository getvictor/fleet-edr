package pipeline

import (
	"encoding/json"
	"fmt"

	rulesapi "github.com/fleetdm/edr/server/rules/api"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// Monitor-mode matches are counted on whichever transition ends a batch's life, and one of those transitions can be reached by an
// attempt that never evaluated. A batch can evaluate, resolve matches and fail at detection, and a LATER attempt can fail at the
// fold and be the one whose nack passes the retry bounds and withdraws it: retry bounds accrue on the queue entry and count every
// attempt whichever stage failed. The evaluating attempt's matches were discarded when it was nacked, and the withdrawing attempt
// has none of its own, so the batch's last word says nothing about what it matched (issue #893).
//
// So the evaluating attempt hands its tally to Nack, which keeps it with the events and gives it back to whoever withdraws them.
// The queue holds the bytes without interpreting them, which is why they cross that boundary encoded: an event queue that knew what
// a monitor match was would be a detection concern living in visibility.
//
// This is the wire shape of those bytes. It is a struct of its own rather than the API type marshalled directly, so renaming a
// field of rulesapi.MonitorMatch cannot silently change what is written: entries persisted by a previous version outlive a rolling
// deploy, since the whole point is that they survive the attempt that wrote them.
type monitorTallyV1 struct {
	Version int              `json:"v"`
	Matches []monitorMatchV1 `json:"matches"`
}

type monitorMatchV1 struct {
	RuleID   string `json:"rule_id"`
	HostID   string `json:"host_id"`
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

const monitorTallyVersion = 1

// encodeMonitorTally renders a tally for Nack to carry, returning nil for an empty one.
//
// Nil rather than an encoding of nothing, because Nack treats "no tally" as "leave what is stored alone", and an empty tally from
// a FAILING attempt is an absence of information rather than an assertion that the batch matched nothing. Evaluation reports what
// it accumulated UP TO its failure (see Engine.Evaluate, which returns tally.snapshot() alongside the error), so an attempt that
// fails on an earlier rule than its predecessor reports fewer matches and one that fails on the first reports none. Encoding an
// empty `matches` here would hand that over as a value and displace what an earlier attempt really resolved, on the commonest
// failure there is, which is the under-reporting issue #893 exists to prevent.
//
// Review proposed the opposite in a later round, having asked for this direction in an earlier one, so the reasoning is written
// down rather than left to be re-derived. The residual it was pointing at is real and accepted: where a rule is taken OUT of
// monitor mode between two attempts, the later attempt's empty tally is a genuine zero and the carried value is the demoted rule's,
// leaving the figure high by one batch for it. The two cases are indistinguishable here, because evaluation reports an empty tally
// for both, and the recorded figure is documented as approximate. Tracked as issue #922 rather than guessed at here.
func encodeMonitorTally(tally rulesapi.MonitorTally) ([]byte, error) {
	if len(tally) == 0 {
		return nil, nil
	}
	wire := monitorTallyV1{Version: monitorTallyVersion, Matches: make([]monitorMatchV1, len(tally))}
	for i, m := range tally {
		wire.Matches[i] = monitorMatchV1{RuleID: m.RuleID, HostID: m.HostID, Severity: m.Severity, Count: m.Count}
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("encode monitor tally: %w", err)
	}
	// The queue's storage for this is finite and refuses an oversized write rather than truncating it, and a refused write fails
	// the nack and leaves the batch in flight until its claim lease expires. Returning the batch is what the nack is for, so an
	// oversized tally has to cost the tally. The input is real rather than hypothetical: one entry per matching rule, and an
	// imported rule pack is operator-sized and defaults to monitor mode.
	if len(encoded) > visibilityapi.MaxNackTallyBytes {
		return nil, fmt.Errorf("encode monitor tally: %d entries encode to %d bytes, over the %d the queue carries",
			len(tally), len(encoded), visibilityapi.MaxNackTallyBytes)
	}
	return encoded, nil
}

// decodeMonitorTally reads back what Nack carried, returning an empty tally for empty bytes.
func decodeMonitorTally(encoded []byte) (rulesapi.MonitorTally, error) {
	if len(encoded) == 0 {
		return nil, nil
	}
	var wire monitorTallyV1
	if err := json.Unmarshal(encoded, &wire); err != nil {
		return nil, fmt.Errorf("decode monitor tally: %w", err)
	}
	if wire.Version != monitorTallyVersion {
		return nil, fmt.Errorf("decode monitor tally: unsupported version %d", wire.Version)
	}
	tally := make(rulesapi.MonitorTally, len(wire.Matches))
	for i, m := range wire.Matches {
		tally[i] = rulesapi.MonitorMatch{RuleID: m.RuleID, HostID: m.HostID, Severity: m.Severity, Count: m.Count}
	}
	return tally, nil
}
