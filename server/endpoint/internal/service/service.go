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
	commandTypeSetBlocklist = "set_blocklist"
	commandTypeRotateToken  = "rotate_token"
)

// Default rotation parameters, applied by the service when bootstrap
// passes zero values. Lifetime = 24 hours matches #86's specified
// default; grace = 5 minutes matches the issue body's "in-flight poll
// must not 401" target.
const (
	defaultHostTokenLifetime = 24 * time.Hour
	defaultHostTokenGrace    = 5 * time.Minute
)

// hardwareUUIDPattern accepts the canonical hyphenated UUID form in
// either case. macOS IOPlatformUUID is uppercase-hyphenated. Future
// platforms emitting unhyphenated 32-hex strings need a matching agent
// + regex update.
var hardwareUUIDPattern = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

// CommandInserter is the closure shape endpoint's enroll fan-out
// uses to queue the initial set_blocklist command. cmd/main passes
// response.Service.Insert as a method value satisfying this type.
// The closure pattern matches what rules uses elsewhere.
type CommandInserter func(ctx context.Context, hostID, commandType string, payload []byte) (int64, error)

// Options bundles every dependency the endpoint service needs. Replaces
// the previous positional-arg constructor: rotation added Audit,
// Lifetime, and Grace to the dep set, and an 8-arg positional
// signature reads like a registry rather than a contract.
type Options struct {
	// Store, Secret, Logger are required.
	Store  *mysql.Store
	Secret string
	Logger *slog.Logger

	// Policy + Commands are an all-or-nothing pair (handler precondition).
	// Both nil disables the post-enroll policy fan-out AND the
	// rotate_token command emission; the rotation will still flip the DB
	// row, but the agent won't get a command to apply the new token, so
	// it'll re-enroll once the grace window expires. Acceptable in tests
	// and the ingest binary; production wires both.
	Policy   api.PolicyProvider
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

// service implements api.Service by composing the mysql.Store with
// the optional PolicyProvider (today: rules.api.PolicyService),
// CommandInserter closure (today: response.api.Service.Insert), and
// audit recorder (today: identity.api.AuditRecorder) that cmd/main
// supplies.
type service struct {
	store    *mysql.Store
	secret   string
	policy   api.PolicyProvider // nil-safe: handler skips fan-out
	commands CommandInserter
	audit    identityapi.AuditRecorder
	lifetime time.Duration
	grace    time.Duration
	logger   *slog.Logger
}

// New constructs a Service. Policy without Commands panics: a
// PolicyProvider that can't queue any command is a config error (the
// enroll handler's post-enroll fan-out has nowhere to send the
// resulting set_blocklist). Commands without Policy is allowed, since
// rotation queues commands without consulting Policy.
func New(opts Options) api.Service {
	if opts.Policy != nil && opts.Commands == nil {
		panic("endpoint service: PolicyProvider set but CommandInserter is nil; policy fan-out has nowhere to go")
	}
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
		policy:   opts.Policy,
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
		// The handler maps this to 400/bad_body via the missing-field check
		// it already does. Service returns ErrInvalidSecret only if secret
		// is non-empty but wrong; an empty secret is a body-shape error.
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

	// Best-effort initial policy fan-out, detached from the request ctx
	// so client cancellation doesn't abort the DB writes. Capped at 10s
	// to match the outer HTTP server's write timeout + slack. gosec G118
	// flags the detached context; the nolint marker is intentional —
	// enrollment already succeeded, the operator is not held up by a
	// flaky command insert, and the next admin policy push re-converges
	// any host whose initial command didn't land.
	if s.policy != nil && s.commands != nil {
		go func(hostID string) { //nolint:gosec,contextcheck // intentional detached context for best-effort fanout
			bgCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			s.enqueueInitialPolicy(bgCtx, hostID)
		}(res.HostID)
	}

	return api.EnrollResponse{
		HostID:     res.HostID,
		HostToken:  res.HostToken,
		EnrolledAt: res.EnrolledAt,
	}, nil
}

// enqueueInitialPolicy fetches the active policy as a pre-marshaled
// command payload and queues a set_blocklist command for the newly-
// enrolled host. Silent on all failures (best-effort). Skips when the
// policy is empty (no paths AND no hashes): pushing an empty command
// is wasted work; the next admin policy PUT will fan out via
// ActiveHostIDs.
func (s *service) enqueueInitialPolicy(ctx context.Context, hostID string) {
	payload, version, hasContent, err := s.policy.ActiveCommandPayload(ctx)
	if err != nil {
		s.logger.WarnContext(ctx, "initial policy fetch failed", attrkeys.HostID, hostID, "err", err)
		return
	}
	if !hasContent {
		s.logger.InfoContext(ctx, "initial policy skipped -- blocklist empty",
			attrkeys.HostID, hostID, "edr.policy.version", version)
		return
	}
	if _, err := s.commands(ctx, hostID, commandTypeSetBlocklist, payload); err != nil {
		s.logger.WarnContext(ctx, "initial policy enqueue failed", attrkeys.HostID, hostID, "err", err)
		return
	}
	s.logger.InfoContext(ctx, "initial policy queued",
		attrkeys.HostID, hostID, "edr.policy.version", version)
}

func (s *service) VerifyToken(ctx context.Context, token string) (string, error) {
	res, err := s.store.VerifyWithMeta(ctx, token)
	if errors.Is(err, mysql.ErrTokenMismatch) {
		return "", api.ErrInvalidToken
	}
	if err != nil {
		return "", fmt.Errorf("verify token: %w", err)
	}

	// Verify-time auto-rotation trigger. Conditions:
	//   - The verify hit the CURRENT token (not the previous-token
	//     grace path; if it hit previous, a rotation is already in
	//     flight and another would be wasteful).
	//   - The current token is past its lifetime.
	// Best-effort: failures are warn-logged but do not fail the verify.
	// The verify already succeeded; the agent's next poll will re-trigger
	// any rotation we couldn't queue this time.
	if !res.MatchedPrevious && time.Since(res.TokenIssuedAt) > s.lifetime {
		s.maybeAutoRotate(ctx, res.HostID, res.CurrentTokenID)
	}

	return res.HostID, nil
}

// maybeAutoRotate is the verify-time auto-rotation path. Optimistic-
// locked on currentTokenID so concurrent verifies for the same host
// don't double-rotate: only the verify whose currentTokenID still
// matches the row's host_token_id commits, the rest race-lose with
// ErrRotateRaced (silently swallowed -- the other verify already did
// the work).
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
	var cmdID *int64
	if s.commands != nil {
		payload, err := json.Marshal(map[string]string{"new_token": rot.NewToken})
		switch {
		case err != nil:
			s.logger.WarnContext(ctx, "rotate_token marshal failed",
				attrkeys.HostID, hostID, "err", err)
		default:
			id, err := s.commands(ctx, hostID, commandTypeRotateToken, payload)
			if err != nil {
				s.logger.WarnContext(ctx, "rotate_token enqueue failed",
					attrkeys.HostID, hostID, "err", err)
			} else {
				cmdID = &id
			}
		}
	}

	if s.audit != nil {
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
	return cmdID
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

// toAPIEnrollment is a struct-to-struct copy. Field shapes match exactly
// today (the api.Enrollment was lifted from the mysql row), so this is a
// pure relocation -- but the conversion stays explicit so a future field
// drift between the storage layer and the public api surface forces a
// review here rather than slipping through.
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
