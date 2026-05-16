package service

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/endpoint/internal/mysql"
	identityapi "github.com/fleetdm/edr/server/identity/api"
)

// Command-type constants for endpoint-emitted commands. Exposed as
// constants so future renames are mechanical.
const (
	commandTypeRotateToken = "rotate_token"
)

// Default rotation parameters, applied by the service when bootstrap passes zero values. Lifetime = 24 hours matches #86's specified
// default; grace = 5 minutes matches the issue body's "in-flight poll must not 401" target.
const (
	defaultHostTokenLifetime = 24 * time.Hour
	defaultHostTokenGrace    = 5 * time.Minute
)

// hardwareUUIDPattern accepts the canonical hyphenated UUID form in either case. macOS IOPlatformUUID is uppercase-hyphenated.
// Future platforms emitting unhyphenated 32-hex strings need a matching agent + regex update.
var hardwareUUIDPattern = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

// CommandInserter is the closure shape endpoint uses to queue commands it emits (today: only rotate_token). cmd/main passes
// response.Service.Insert as a method value satisfying this type. The closure pattern matches what rules uses elsewhere.
type CommandInserter func(ctx context.Context, hostID, commandType string, payload []byte) (int64, error)

// Options bundles every dependency the endpoint service needs.
type Options struct {
	// Store, Secret, Logger are required.
	Store  *mysql.Store
	Secret string
	Logger *slog.Logger

	// Commands queues commands the endpoint service emits (today: only rotate_token). Optional: when nil, rotation will commit the new
	// bearer in the DB but the agent will not receive a command — it will re-enroll once the grace window expires.
	Commands CommandInserter

	// Audit is the operator-action audit recorder. Nil disables audit
	// emission for token rotations; tests that don't care can pass nil.
	Audit identityapi.AuditRecorder

	// Lifetime is the maximum age of a current token before the verify
	// path triggers an auto-rotation. Zero -> defaultHostTokenLifetime.
	Lifetime time.Duration
	// Grace is the window during which the just-superseded token still
	// verifies after rotation. Zero -> defaultHostTokenGrace.
	Grace time.Duration
}

// service implements api.Service by composing the mysql.Store with the CommandInserter closure (today: response.api.Service.Insert)
// and audit recorder (today: identity.api.AuditRecorder) that cmd/main supplies.
type service struct {
	store    *mysql.Store
	secret   string
	commands CommandInserter
	audit    identityapi.AuditRecorder
	lifetime time.Duration
	grace    time.Duration
	logger   *slog.Logger
}

// New constructs a Service.
func New(opts Options) api.Service {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	lifetime := opts.Lifetime
	if lifetime <= 0 {
		lifetime = defaultHostTokenLifetime
	}
	grace := opts.Grace
	if grace <= 0 {
		grace = defaultHostTokenGrace
	}
	return &service{
		store:    opts.Store,
		secret:   opts.Secret,
		commands: opts.Commands,
		audit:    opts.Audit,
		lifetime: lifetime,
		grace:    grace,
		logger:   logger,
	}
}

func (s *service) Enroll(ctx context.Context, req api.EnrollRequest, sourceIP string) (api.EnrollResponse, error) {
	if req.EnrollSecret == "" || req.HardwareUUID == "" || req.Hostname == "" ||
		req.OSVersion == "" || req.AgentVersion == "" {
		// The handler maps this to 400/bad_body via the missing-field check it already does. Service returns ErrInvalidSecret
		// only if secret is non-empty but wrong; an empty secret is a body-shape error.
		return api.EnrollResponse{}, api.ErrInvalidEnrollRequest
	}
	if !hardwareUUIDPattern.MatchString(req.HardwareUUID) {
		return api.EnrollResponse{}, api.ErrInvalidHardwareUUID
	}
	// Constant-time compare. Never log the secret value.
	if subtle.ConstantTimeCompare([]byte(req.EnrollSecret), []byte(s.secret)) != 1 {
		return api.EnrollResponse{}, api.ErrInvalidSecret
	}
	res, err := s.store.Register(ctx, mysql.RegisterRequest{
		HostID:       req.HardwareUUID,
		Hostname:     req.Hostname,
		AgentVersion: req.AgentVersion,
		OSVersion:    req.OSVersion,
		SourceIP:     sourceIP,
	})
	if err != nil {
		return api.EnrollResponse{}, fmt.Errorf("register enrollment: %w", err)
	}

	return api.EnrollResponse{
		HostID:     res.HostID,
		HostToken:  res.HostToken,
		EnrolledAt: res.EnrolledAt,
	}, nil
}

func (s *service) VerifyToken(ctx context.Context, token string) (string, error) {
	res, err := s.store.VerifyWithMeta(ctx, token)
	if errors.Is(err, mysql.ErrTokenMismatch) {
		return "", api.ErrInvalidToken
	}
	if err != nil {
		return "", fmt.Errorf("verify token: %w", err)
	}

	// Verify-time auto-rotation trigger. Conditions: the verify hit the CURRENT token (not the previous-token grace path; if it
	// hit previous, a rotation is already in flight and another would be wasteful) AND the current token is past its lifetime.
	// Best-effort: failures are warn-logged but do not fail the verify. The verify already succeeded; the agent's next poll will
	// re-trigger any rotation we couldn't queue this time.
	if !res.MatchedPrevious && time.Since(res.TokenIssuedAt) > s.lifetime {
		s.maybeAutoRotate(ctx, res.HostID, res.CurrentTokenID)
	}

	return res.HostID, nil
}

// maybeAutoRotate is the verify-time auto-rotation path. Optimistic- locked on currentTokenID so concurrent verifies for the same host
// don't double-rotate: only the verify whose currentTokenID still matches the row's host_token_id commits, the rest race-lose with
// ErrRotateRaced (silently swallowed -- the other verify already did the work).
func (s *service) maybeAutoRotate(ctx context.Context, hostID string, currentTokenID []byte) {
	rot, err := s.store.RotateHostToken(ctx, hostID, currentTokenID, s.grace)
	if errors.Is(err, mysql.ErrRotateRaced) {
		return
	}
	if err != nil {
		s.logger.WarnContext(ctx, "auto-rotate failed",
			attrkeys.HostID, hostID, "err", err)
		return
	}
	s.deliverRotation(ctx, hostID, api.RotationTriggerAuto, "", "", rot)
}

func (s *service) RotateToken(ctx context.Context, hostID string, trigger api.RotationTrigger, actor, reason string) (api.RotateResult, error) {
	if hostID == "" {
		return api.RotateResult{}, fmt.Errorf("rotate token: %w", api.ErrNotFound)
	}
	rot, err := s.store.RotateHostTokenForce(ctx, hostID, s.grace)
	if errors.Is(err, mysql.ErrNotFound) {
		return api.RotateResult{}, api.ErrNotFound
	}
	if err != nil {
		return api.RotateResult{}, fmt.Errorf("rotate token: %w", err)
	}
	return api.RotateResult{
		PreviousTokenIDPrefix: rot.PreviousTokenIDPrefix,
		CommandID:             s.deliverRotation(ctx, hostID, trigger, actor, reason, rot),
	}, nil
}

// deliverRotation queues the rotate_token command for the agent and
// emits the audit row. Shared between the verify-time auto path and
// the operator-driven RotateToken path so both audit row shapes are
// byte-identical except for the trigger / actor / reason payload
// fields. Returns *int64: a non-nil pointer carries the freshly-queued
// command id, nil signals "rotation committed in the DB but the agent
// command queue did not receive the new bearer." The operator UI uses
// the nil case to surface "agent will recover via re-enroll once the
// previous-token grace expires" rather than waiting indefinitely for
// an ack.
//
// Best-effort on the command insert: rotation already committed in
// the DB. If we can't queue the rotate_token command, the agent's
// previous token still works during grace; once grace expires it'll
// 401 and re-enroll. Acceptable failure mode for a queue hiccup.
//
// Best-effort on the audit emit too: a missed audit row is a follow-up
// incident, not a reason to fail an HTTP response that already
// returned 200/204.
func (s *service) deliverRotation(ctx context.Context, hostID string, trigger api.RotationTrigger, actor, reason string, rot mysql.RotateResult) *int64 {
	cmdID := s.enqueueRotateCommand(ctx, hostID, rot.NewToken)
	s.recordRotationAudit(ctx, hostID, trigger, actor, reason, rot, cmdID)
	return cmdID
}

func (s *service) enqueueRotateCommand(ctx context.Context, hostID, newToken string) *int64 {
	if s.commands == nil {
		return nil
	}
	// json.Marshal on map[string]string cannot fail (UTF-8 string keys + values always serialize); the err is intentionally dropped so the
	// call has no unreachable branch dragging coverage down.
	payload, _ := json.Marshal(map[string]string{"new_token": newToken}) //nolint:errcheck // map[string]string never fails to marshal
	id, err := s.commands(ctx, hostID, commandTypeRotateToken, payload)
	if err != nil {
		s.logger.WarnContext(ctx, "rotate_token enqueue failed",
			attrkeys.HostID, hostID, "err", err)
		return nil
	}
	return &id
}

func (s *service) recordRotationAudit(ctx context.Context, hostID string, trigger api.RotationTrigger, actor, reason string, rot mysql.RotateResult, cmdID *int64) {
	if s.audit == nil {
		return
	}
	payload := map[string]any{
		"trigger":                  string(trigger),
		"previous_token_id_prefix": rot.PreviousTokenIDPrefix,
	}
	if actor != "" {
		payload["actor"] = actor
	}
	if reason != "" {
		payload["reason"] = reason
	}
	if cmdID != nil {
		payload["command_id"] = *cmdID
	}
	if err := s.audit.Record(ctx, identityapi.AuditEvent{
		Action:     identityapi.AuditEnrollmentRotateToken,
		TargetType: "host",
		TargetID:   hostID,
		Payload:    payload,
	}); err != nil {
		s.logger.WarnContext(ctx, "audit record failed",
			attrkeys.HostID, hostID,
			"action", string(identityapi.AuditEnrollmentRotateToken),
			"err", err)
	}
}

func (s *service) List(ctx context.Context) ([]api.Enrollment, error) {
	rows, err := s.store.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list enrollments: %w", err)
	}
	out := make([]api.Enrollment, len(rows))
	for i, r := range rows {
		out[i] = toAPIEnrollment(r)
	}
	return out, nil
}

func (s *service) Get(ctx context.Context, hostID string) (*api.Enrollment, error) {
	row, err := s.store.Get(ctx, hostID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, api.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get enrollment: %w", err)
	}
	out := toAPIEnrollment(*row)
	return &out, nil
}

func (s *service) Revoke(ctx context.Context, hostID, reason, actor string) error {
	err := s.store.Revoke(ctx, hostID, reason, actor)
	if errors.Is(err, sql.ErrNoRows) {
		return api.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("revoke enrollment: %w", err)
	}
	return nil
}

func (s *service) CountActive(ctx context.Context) (int, error) {
	return s.store.CountActive(ctx)
}

func (s *service) ActiveHostIDs(ctx context.Context) ([]string, error) {
	return s.store.ActiveHostIDs(ctx)
}

// toAPIEnrollment is a struct-to-struct copy. Field shapes match exactly today (the api.Enrollment was lifted from the mysql row),
// so this is a pure relocation -- but the conversion stays explicit so a future field drift between the storage layer and the public
// api surface forces a review here rather than slipping through.
func toAPIEnrollment(r mysql.Enrollment) api.Enrollment {
	return api.Enrollment{
		HostID:       r.HostID,
		Hostname:     r.Hostname,
		AgentVersion: r.AgentVersion,
		OSVersion:    r.OSVersion,
		SourceIP:     r.SourceIP,
		EnrolledAt:   r.EnrolledAt,
		ExpiresAt:    r.ExpiresAt,
		RevokedAt:    r.RevokedAt,
		RevokeReason: r.RevokeReason,
		RevokedBy:    r.RevokedBy,
	}
}
