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
// control-channel client can recognize a terminal outcome (to cache it for idempotent re-report on re-delivery).
const (
	StatusAcked     = "acked"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
)

// invalidPayloadPrefix is the reason prefix every handler emits when json.Unmarshal of cmd.Payload fails. Centralised so the wire shape
// stays stable across handlers.
const invalidPayloadPrefix = "invalid payload: "

// ReportFunc records a status transition for a command. The command id is bound by the caller (each transport reports over its own
// channel: the poll path PUTs /api/commands/{id}; the control channel sends an Outcome frame). A non-nil error means the report did not
// reach the server.
type ReportFunc func(ctx context.Context, status string, result json.RawMessage) error

// Executor runs a command's local side effect and reports its outcome through a transport-supplied ReportFunc. It holds no transport
// state, so the poll loop and the control-channel client share one instance's worth of behavior without coupling to how commands are
// delivered or how outcomes are sent back.
type Executor struct {
	sender ApplicationControlSender
	// kill is the process-termination syscall, injectable so tests exercise the kill_process path without signalling a real process.
	kill   func(pid int, sig syscall.Signal) error
	logger *slog.Logger
}

// NewExecutor builds an Executor. sender may be nil (set_application_control then reports failed with a clear reason); logger nil uses
// the default.
func NewExecutor(sender ApplicationControlSender, logger *slog.Logger) *Executor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Executor{sender: sender, kill: syscall.Kill, logger: logger}
}

// Execute drives one command through the acknowledged-then-completed-or-failed lifecycle: it reports acked first (so an operator never
// sees a stuck pending command after work has begun), runs the type-specific side effect, then reports the terminal outcome. If the
// acked report fails the side effect is skipped, leaving the command eligible for re-dispatch. Unknown types fail explicitly.
func (e *Executor) Execute(ctx context.Context, cmd Command, report ReportFunc) {
	if err := report(ctx, StatusAcked, nil); err != nil {
		e.logger.ErrorContext(ctx, "commander ack", "cmd_id", cmd.ID, "err", err)
		return
	}
	switch cmd.CommandType {
	case "kill_process":
		e.executeKill(ctx, cmd, report)
	case "set_application_control":
		e.executeSetApplicationControl(ctx, cmd, report)
	default:
		if err := report(ctx, StatusFailed, marshalResult("unknown command type: "+cmd.CommandType)); err != nil {
			e.logger.ErrorContext(ctx, "commander fail", "cmd_id", cmd.ID, "err", err)
		}
	}
}

func (e *Executor) executeKill(ctx context.Context, cmd Command, report ReportFunc) {
	var payload killPayload
	if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
		_ = report(ctx, StatusFailed, marshalResult(invalidPayloadPrefix+err.Error()))
		return
	}
	if payload.PID <= 0 {
		_ = report(ctx, StatusFailed, marshalResult("invalid pid"))
		return
	}
	e.logger.InfoContext(ctx, "commander kill_process", "pid", payload.PID, "cmd_id", cmd.ID)
	if err := e.kill(payload.PID, syscall.SIGKILL); err != nil {
		if reportErr := report(ctx, StatusFailed, marshalResult(err.Error())); reportErr != nil {
			e.logger.ErrorContext(ctx, "commander report kill failure", "cmd_id", cmd.ID, "err", reportErr)
		}
		return
	}
	successResult, _ := json.Marshal(map[string]int{"killed_pid": payload.PID})
	if err := report(ctx, StatusCompleted, successResult); err != nil {
		e.logger.ErrorContext(ctx, "commander report kill success", "cmd_id", cmd.ID, "err", err)
	}
}

// executeSetApplicationControl forwards the raw command payload to the ESF extension over XPC. Result on success is
// {"policy_id": P, "policy_version": V} so operators can confirm per host which snapshot the agent applied. Envelope validation only
// (policy_id present, version positive, rules is a JSON array); the per-rule shape is the extension's responsibility, and forwarding the
// raw bytes keeps the wire shape byte-identical across server, agent, and extension.
func (e *Executor) executeSetApplicationControl(ctx context.Context, cmd Command, report ReportFunc) {
	var payload setApplicationControlPayload
	if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
		_ = report(ctx, StatusFailed, marshalResult(invalidPayloadPrefix+err.Error()))
		return
	}
	if payload.PolicyID <= 0 {
		_ = report(ctx, StatusFailed, marshalResult("payload missing or invalid policy_id"))
		return
	}
	if payload.PolicyVersion <= 0 {
		// Versioning is the ordering guard for snapshot state on the extension; a zero/negative version would either mask an
		// out-of-order delivery or reflect a hand-queued test command that shouldn't be acted on. Fail fast so the audit trail
		// attributes the error to its source rather than to opaque XPC decode errors from the extension.
		_ = report(ctx, StatusFailed, marshalResult("invalid policy_version"))
		return
	}
	if !isJSONArray(payload.Rules) {
		_ = report(ctx, StatusFailed, marshalResult("payload missing or invalid rules array"))
		return
	}
	if e.sender == nil {
		_ = report(ctx, StatusFailed, marshalResult("application control sender not configured"))
		return
	}
	e.logger.InfoContext(ctx, "commander set_application_control",
		"cmd_id", cmd.ID,
		"edr.app_control.policy_id", payload.PolicyID,
		"edr.app_control.policy_version", payload.PolicyVersion,
	)
	// Forward the raw JSON bytes so the extension parses the same shape the server wrote. The send is async: completing here does NOT
	// mean the extension has applied the snapshot; the audit trail of "command completed on agent" is sufficient for now.
	if err := e.sender.SendApplicationControl([]byte(cmd.Payload)); err != nil {
		_ = report(ctx, StatusFailed, marshalResult("xpc send: "+err.Error()))
		return
	}
	result, _ := json.Marshal(map[string]any{
		"policy_id":      payload.PolicyID,
		"policy_version": payload.PolicyVersion,
	})
	if err := report(ctx, StatusCompleted, result); err != nil {
		e.logger.ErrorContext(ctx, "commander report set_application_control success", "cmd_id", cmd.ID, "err", err)
	}
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
