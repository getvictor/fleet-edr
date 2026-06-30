package commander

import (
	"context"
	"encoding/json"
	"log/slog"
	"syscall"
)

// Command is the agent-side view of a server command to execute. The json tags decode the poll-path response body; the control-channel
// client builds the same struct from the pushed gRPC frame. Shared so both transports run one execution path.
type Command struct {
	ID          int64           `json:"id"`
	HostID      string          `json:"host_id"`
	CommandType string          `json:"command_type"`
	Payload     json.RawMessage `json:"payload"`
	Status      string          `json:"status"`
}

// Status values the executor reports through ReportFunc. They mirror the server-side command lifecycle and are exported so the
// control-channel client can recognize a terminal outcome.
const (
	StatusAcked     = "acked"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
)

// statusExecuting is an agent-local ledger status, never reported to the server. It is the write-ahead claim the executor records
// before running a side effect: if the agent crashes mid-execution, a re-delivery finds this status and refuses to re-run the side
// effect (see Execute), which is the safety guard against re-killing a since-reused PID.
const statusExecuting = "executing"

// Ledger is the durable, cross-transport dedup store the executor keys execution on (issue #558). It is satisfied by
// commandledger.Store; both transports share one instance so a command executed on either path, in this process run or a prior one,
// is not re-executed. A nil Ledger disables dedup (tests, and a degraded path if the ledger cannot be opened).
type Ledger interface {
	// Lookup returns the recorded status and result for a command id; seen is false if the id is unknown.
	Lookup(ctx context.Context, id int64) (status string, result json.RawMessage, seen bool, err error)
	// Mark upserts the status (and result) for a command id.
	Mark(ctx context.Context, id int64, status string, result json.RawMessage) error
}

// invalidPayloadPrefix is the reason prefix every handler emits when json.Unmarshal of cmd.Payload fails. Centralised so the wire shape
// stays stable across handlers.
const invalidPayloadPrefix = "invalid payload: "

// ReportFunc records a status transition for a command. The command id is bound by the caller (each transport reports over its own
// channel: the poll path PUTs /api/commands/{id}; the control channel sends an Outcome frame). A non-nil error means the report did not
// reach the server.
type ReportFunc func(ctx context.Context, status string, result json.RawMessage) error

// Executor runs a command's local side effect and reports its outcome through a transport-supplied ReportFunc. It holds no transport
// state, so the poll loop and the control-channel client share one instance's worth of behavior without coupling to how commands are
// delivered or how outcomes are sent back. A shared Ledger gives it durable, cross-transport at-most-once execution.
type Executor struct {
	sender ApplicationControlSender
	ledger Ledger
	// kill is the process-termination syscall, injectable so tests exercise the kill_process path without signalling a real process.
	kill   func(pid int, sig syscall.Signal) error
	logger *slog.Logger
}

// NewExecutor builds an Executor. sender may be nil (set_application_control then reports failed with a clear reason); ledger may be nil
// (dedup disabled, for tests or a degraded path if the ledger cannot be opened); logger nil uses the default.
func NewExecutor(sender ApplicationControlSender, ledger Ledger, logger *slog.Logger) *Executor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Executor{sender: sender, ledger: ledger, kill: syscall.Kill, logger: logger}
}

// Execute drives one command through the acknowledged-then-completed-or-failed lifecycle, deduplicated by command identity via the
// shared Ledger so the side effect runs at most once across transports and across restarts (issue #558):
//
//   - If the ledger already has a terminal outcome for the command (executed earlier, on either transport or a prior process run), it
//     re-acks and replays that outcome WITHOUT re-running the side effect, so a command whose outcome report was lost still transitions
//     out of pending rather than being re-executed (re-killing a possibly-reused PID).
//   - If the ledger has a write-ahead "executing" claim with no terminal outcome, a prior attempt was interrupted (a crash between the
//     side effect and recording its result). The side effect is NOT re-run; the command is terminalized as failed so the server stops
//     re-delivering it and an operator can re-issue against the current process.
//   - Otherwise it acks (skipping the side effect and leaving the command eligible for re-dispatch if the ack fails), records the
//     write-ahead claim, runs the side effect, records the terminal outcome, then reports it.
func (e *Executor) Execute(ctx context.Context, cmd Command, report ReportFunc) {
	if e.replayIfSeen(ctx, cmd, report) {
		return
	}
	if err := report(ctx, StatusAcked, nil); err != nil {
		e.logger.ErrorContext(ctx, "commander ack", "cmd_id", cmd.ID, "err", err)
		return // ack did not reach the server: leave the command eligible for re-dispatch, with no ledger claim recorded.
	}
	e.mark(ctx, cmd.ID, statusExecuting, nil) // write-ahead: claim before the side effect so a crash mid-execution is not re-run.
	status, result := e.run(ctx, cmd)
	e.mark(ctx, cmd.ID, status, result)
	if err := report(ctx, status, result); err != nil {
		e.logger.ErrorContext(ctx, "commander report outcome", "cmd_id", cmd.ID, "status", status, "err", err)
	}
}

// replayIfSeen consults the ledger; it returns true when the command was already seen and was handled here (replayed terminal outcome,
// or terminalized as failed for an interrupted prior attempt) so Execute must not run the side effect.
func (e *Executor) replayIfSeen(ctx context.Context, cmd Command, report ReportFunc) bool {
	if e.ledger == nil {
		return false
	}
	status, result, seen, err := e.ledger.Lookup(ctx, cmd.ID)
	if err != nil {
		// A ledger read error must not wedge command delivery; log and fall through to execute (dedup degraded for this command).
		e.logger.ErrorContext(ctx, "command ledger lookup", "cmd_id", cmd.ID, "err", err)
		return false
	}
	if !seen {
		return false
	}
	_ = report(ctx, StatusAcked, nil) // re-ack: drives the server out of pending if the earlier ack was lost; a dup ack is benign.
	if status == StatusCompleted || status == StatusFailed {
		_ = report(ctx, status, result) // replay the recorded terminal outcome; no side effect.
		return true
	}
	// "executing" with no terminal outcome: a prior attempt was interrupted. Do not re-run a non-idempotent side effect.
	res := marshalResult("not retried: a prior execution attempt did not complete")
	e.mark(ctx, cmd.ID, StatusFailed, res)
	_ = report(ctx, StatusFailed, res)
	return true
}

// mark records a status in the ledger, logging (not propagating) a failure: a ledger write error degrades dedup for one command but
// must not stop the command from being executed and reported.
func (e *Executor) mark(ctx context.Context, id int64, status string, result json.RawMessage) {
	if e.ledger == nil {
		return
	}
	if err := e.ledger.Mark(ctx, id, status, result); err != nil {
		e.logger.ErrorContext(ctx, "command ledger mark", "cmd_id", id, "status", status, "err", err)
	}
}

// run executes a command's type-specific side effect and returns its terminal outcome. It performs no reporting and no ledger writes;
// Execute owns those so dedup and outcome recording are uniform across command types.
func (e *Executor) run(ctx context.Context, cmd Command) (status string, result json.RawMessage) {
	switch cmd.CommandType {
	case "kill_process":
		return e.runKill(ctx, cmd)
	case "set_application_control":
		return e.runSetApplicationControl(ctx, cmd)
	default:
		return StatusFailed, marshalResult("unknown command type: " + cmd.CommandType)
	}
}

func (e *Executor) runKill(ctx context.Context, cmd Command) (string, json.RawMessage) {
	var payload killPayload
	if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
		return StatusFailed, marshalResult(invalidPayloadPrefix + err.Error())
	}
	if payload.PID <= 0 {
		return StatusFailed, marshalResult("invalid pid")
	}
	e.logger.InfoContext(ctx, "commander kill_process", "pid", payload.PID, "cmd_id", cmd.ID)
	if err := e.kill(payload.PID, syscall.SIGKILL); err != nil {
		return StatusFailed, marshalResult(err.Error())
	}
	successResult, _ := json.Marshal(map[string]int{"killed_pid": payload.PID})
	return StatusCompleted, successResult
}

// runSetApplicationControl forwards the raw command payload to the ESF extension over XPC. Result on success is
// {"policy_id": P, "policy_version": V} so operators can confirm per host which snapshot the agent applied. Envelope validation only
// (policy_id present, version positive, rules is a JSON array); the per-rule shape is the extension's responsibility, and forwarding the
// raw bytes keeps the wire shape byte-identical across server, agent, and extension.
func (e *Executor) runSetApplicationControl(ctx context.Context, cmd Command) (string, json.RawMessage) {
	var payload setApplicationControlPayload
	if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
		return StatusFailed, marshalResult(invalidPayloadPrefix + err.Error())
	}
	if payload.PolicyID <= 0 {
		return StatusFailed, marshalResult("payload missing or invalid policy_id")
	}
	if payload.PolicyVersion <= 0 {
		// Versioning is the ordering guard for snapshot state on the extension; a zero/negative version would either mask an
		// out-of-order delivery or reflect a hand-queued test command that shouldn't be acted on. Fail fast so the audit trail
		// attributes the error to its source rather than to opaque XPC decode errors from the extension.
		return StatusFailed, marshalResult("invalid policy_version")
	}
	if !isJSONArray(payload.Rules) {
		return StatusFailed, marshalResult("payload missing or invalid rules array")
	}
	if e.sender == nil {
		return StatusFailed, marshalResult("application control sender not configured")
	}
	e.logger.InfoContext(ctx, "commander set_application_control",
		"cmd_id", cmd.ID,
		"edr.app_control.policy_id", payload.PolicyID,
		"edr.app_control.policy_version", payload.PolicyVersion,
	)
	// Forward the raw JSON bytes so the extension parses the same shape the server wrote. The send is async: completing here does NOT
	// mean the extension has applied the snapshot; the audit trail of "command completed on agent" is sufficient for now.
	if err := e.sender.SendApplicationControl([]byte(cmd.Payload)); err != nil {
		return StatusFailed, marshalResult("xpc send: " + err.Error())
	}
	result, _ := json.Marshal(map[string]any{
		"policy_id":      payload.PolicyID,
		"policy_version": payload.PolicyVersion,
	})
	return StatusCompleted, result
}

type killPayload struct {
	PID int `json:"pid"`
}

// setApplicationControlPayload mirrors server/rules/api.SetApplicationControlPayload. Field names + json tags are load-bearing: the
// extension parses the same JSON bytes and the byte-shape must match across all three sides.
type setApplicationControlPayload struct {
	PolicyID      int64 `json:"policy_id"`
	PolicyVersion int64 `json:"policy_version"`
	// Rules is decoded as json.RawMessage so the agent doesn't need to know the rule shape; the extension is the source of truth.
	Rules json.RawMessage `json:"rules"`
}

// marshalResult builds a properly-escaped JSON result with an error field.
func marshalResult(errMsg string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{"error": errMsg})
	return b
}

// isJSONArray reports whether raw is a JSON array (including the empty array). Used by the set_application_control envelope check to
// reject payloads with missing or null `rules` fields, which would otherwise slip through json.Unmarshal-into-json.RawMessage and only
// fail at extension decode time after the server has already seen `completed`.
func isJSONArray(raw json.RawMessage) bool {
	for _, b := range raw {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case '[':
			return true
		default:
			return false
		}
	}
	return false
}
