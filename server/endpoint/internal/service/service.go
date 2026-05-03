package service

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/endpoint/internal/mysql"
)

// commandTypeSetBlocklist is the only command-type endpoint emits at
// enroll time today. Exposed as a constant rather than scattered string
// literals so future renames are mechanical.
const commandTypeSetBlocklist = "set_blocklist"

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

// service implements api.Service by composing the mysql.Store with
// the optional PolicyProvider (today: rules.api.PolicyService) and
// CommandInserter closure (today: response.api.Service.Insert) that
// cmd/main supplies.
type service struct {
	store    *mysql.Store
	secret   string
	policy   api.PolicyProvider // nil-safe: handler skips fan-out
	commands CommandInserter
	logger   *slog.Logger
}

// New constructs a Service. All inputs (other than the optional policy/
// commands pair) are required to be non-nil; bootstrap.New is the only
// caller in production and validates them upfront.
//
// PolicyProvider and CommandInserter are an all-or-nothing pair: if one
// is set the other must be too (panic otherwise). This matches the
// existing enrollment.NewHandler precondition.
func New(s *mysql.Store, secret string, policy api.PolicyProvider, cmds CommandInserter, logger *slog.Logger) api.Service {
	if (policy != nil) != (cmds != nil) {
		panic("endpoint service: PolicyProvider and CommandInserter must be set together or both nil")
	}
	return &service{
		store:    s,
		secret:   secret,
		policy:   policy,
		commands: cmds,
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
	hostID, err := s.store.Verify(ctx, token)
	if errors.Is(err, mysql.ErrTokenMismatch) {
		return "", api.ErrInvalidToken
	}
	if err != nil {
		return "", fmt.Errorf("verify token: %w", err)
	}
	return hostID, nil
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
