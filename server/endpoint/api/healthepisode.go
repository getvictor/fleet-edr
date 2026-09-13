package api

import (
	"context"

	"github.com/fleetdm/edr/server/sqlhelpers"
)

// NullRawJSON is the shared JSON-or-NULL column type, aliased here so this context's callers do not import sqlhelpers directly.
// Matches how detection/api exposes the same type.
type NullRawJSON = sqlhelpers.NullRawJSON

// HealthEpisodeKind names a class of component fault that an episode records. Open-vocabulary for the same reason the status
// snapshot's component types and reasons are: a new health signal should be a producer-side change, not a schema migration.
type HealthEpisodeKind = string

// KindSelfHealFailed is the first kind: this product's automatic repair of a stopped capture provider exhausted its attempts, so
// the host stays uncaptured until a person acts. It is deliberately spelled the same as the agent's own health reason for the
// condition, so the record and the level state that reports it read as one thing.
const KindSelfHealFailed HealthEpisodeKind = "self_heal_failed"

// The widths the episode's identifying columns are stored at. Exported because the producer has to respect them: a value that does
// not fit fails the insert, and that failure reaches the caller as a persistence error, which nacks the whole event batch and has it
// retried forever. A producer that cannot fit its value refuses the finding instead, which costs one report rather than a stuck
// queue. These are ours-to-ours values (the agent reports registered component and provider names), so exceeding them means a
// malformed or hostile report rather than a legitimate long name.
const (
	MaxHealthComponentLen = 64
	MaxHealthSubjectLen   = 128
	MaxHealthKindLen      = 64
)

// HealthEpisode is a component fault that needed a person, recorded as an interval rather than as level state.
//
// It exists because the two questions an operator asks have different shapes. "Is this host capturing right now" is level state
// and lives in the status snapshot, which is overwritten the moment the answer changes. "Was this host ever not capturing, and for
// how long" cannot be answered from level state at all: once someone fixes the host by hand it reads healthy, and nothing says it
// was ever broken. An episode is the second answer. It opens when the fault is reported and closes when the component reports
// healthy again, so the interval between is the outage.
//
// Detail carries the fault's own machine-readable fields (for KindSelfHealFailed: the provider, the outcome, and the attempt
// count) rather than leaving a reader to parse them back out of Description. The shape is per-kind by design, which is why it is
// a JSON document here and not a set of columns: a second kind should not require a migration to record what it knows.
type HealthEpisode struct {
	ID        int64  `db:"id" json:"id"`
	HostID    string `db:"host_id" json:"host_id"`
	Component string `db:"component" json:"component"`
	// Subject is WHICH thing inside the component is at fault (for a capture-provider failure, the provider). Data an operator reads
	// and filters on, not identity: two providers failing under one extension are two outages because they arrive as two events.
	Subject string            `db:"subject" json:"subject,omitempty"`
	Kind    HealthEpisodeKind `db:"kind" json:"kind"`
	// SourceEventID is the occurrence this episode records, and with the host it is the episode's identity.
	//
	// The producer emits one event per outage, so the only repetition the server sees is REDELIVERY of that event: delivery is
	// at-least-once, so a batch can be evaluated, acked poorly, and evaluated again. Keying on the occurrence collapses those onto
	// one record whether or not the episode has closed in between, and lets a genuinely later outage open its own because it
	// carries its own event. It is the same identity the alert this replaced deduplicated on.
	SourceEventID string      `db:"source_event_id" json:"source_event_id"`
	Severity      string      `db:"severity" json:"severity"`
	Title         string      `db:"title" json:"title"`
	Description   string      `db:"description" json:"description,omitempty"`
	Detail        NullRawJSON `db:"detail" json:"detail,omitempty"`
	// OpenedAtNs and ResolvedAtNs are both AGENT-observed instants, not server processing times. The interval between them is the
	// whole value of the record, and mixing the two clocks would measure queue backlog and delivery delay as part of the outage, or
	// on a skewed host produce a resolution before its own opening.
	OpenedAtNs   int64  `db:"opened_at_ns" json:"opened_at_ns"`
	ResolvedAtNs *int64 `db:"resolved_at_ns" json:"resolved_at_ns,omitempty"`
}

// RecoveredComponent is one component a status snapshot reports healthy, with the agent-observed instant it entered that state.
// The instant is carried rather than the snapshot's report time so the episode's end is when the component actually recovered, not
// when we happened to hear about it.
type RecoveredComponent struct {
	Type string
	AtNs int64
}

// Open reports whether the fault is still in effect. An open episode is a host that needs attention now; a closed one is history
// with a measurable duration.
func (e HealthEpisode) Open() bool { return e.ResolvedAtNs == nil }

// SelfHealFailedDetail is the Detail shape for KindSelfHealFailed. The three fields are what make the fault actionable: which
// provider to restore, which failure shape was reached (the repair command failing implicates the host application or the
// configuration daemon, while repairs reporting success on a provider that stays stopped means re-enabling is not what the fault
// needs), and that the repair was genuinely attempted rather than skipped.
type SelfHealFailedDetail struct {
	Provider string `json:"provider"`
	Outcome  string `json:"outcome"`
	Attempts int    `json:"attempts"`
}

// HealthEpisodeRecorder is the write surface another bounded context depends on to record a fault it observed. The detection
// engine holds one: it evaluates the agent's report and decides that the finding is a health signal rather than a detection, but
// host health is the endpoint context's to own, so the engine states the fact and this context decides what storing it means.
//
// OpenHealthEpisode is idempotent on the occurrence it records, so a redelivered event collapses onto the episode it already opened
// rather than opening a second one for an outage that is already recorded.
type HealthEpisodeRecorder interface {
	OpenHealthEpisode(ctx context.Context, e HealthEpisode) (opened bool, err error)
}
