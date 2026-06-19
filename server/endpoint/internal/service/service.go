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
	"github.com/fleetdm/edr/server/endpoint/internal/revocation"
	"github.com/fleetdm/edr/server/endpoint/internal/signedtoken"
	identityapi "github.com/fleetdm/edr/server/identity/api"
)

// defaultTokenTTL is how long a freshly minted signed host token is valid. The agent refreshes well before this (see the agent refresh
// loop), so a live host never lets its token expire; the TTL bounds how long a stolen token survives if revocation somehow lagged. 60
// minutes matches the SPIFFE guidance for hot-path workload identities.
const defaultTokenTTL = 60 * time.Minute

// CommandInserter is retained for wiring compatibility (the bootstrap alias + cmd/main type references). The endpoint context no longer
// emits commands under the self-validating-token model: token refresh is agent-pull, and credential cycling is an epoch bump enforced
// by the revocation snapshot, not a server-pushed rotate_token command.
type CommandInserter func(ctx context.Context, hostID, commandType string, payload []byte) (int64, error)

// hardwareUUIDPattern accepts the canonical hyphenated UUID form in either case. macOS IOPlatformUUID is uppercase-hyphenated. Future
// platforms emitting unhyphenated 32-hex strings need a matching agent + regex update.
var hardwareUUIDPattern = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

// Options bundles every dependency the endpoint service needs.
type Options struct {
	// Store, Secret, Signer, Revocations, Logger are required.
	Store       *mysql.Store
	Secret      string
	Signer      *signedtoken.Signer
	Revocations *revocation.Snapshot
	Logger      *slog.Logger

	// Audit is the operator-action audit recorder. Nil disables audit emission for credential cycling; tests that don't care pass nil.
	Audit identityapi.AuditRecorder

	// TokenTTL is the lifetime of a minted host token. Zero -> defaultTokenTTL (60m).
	TokenTTL time.Duration
}

// service implements api.Service. Verification is a local signature check (signer) plus an in-memory revocation lookup (revocations),
// so the agent hot path never touches the database. The store is used only on the rare paths: enroll, refresh (one read), credential
// cycling, and operator listings.
type service struct {
	store       *mysql.Store
	secret      string
	signer      *signedtoken.Signer
	revocations *revocation.Snapshot
	audit       identityapi.AuditRecorder
	tokenTTL    time.Duration
	logger      *slog.Logger
}

// New constructs a Service. Panics on a missing Store, Signer, or Revocations: those are wiring bugs (the only callers are bootstrap,
// which validates first, and tests), not recoverable runtime conditions.
func New(opts Options) api.Service {
	if opts.Store == nil {
		panic("service.New: Store is required")
	}
	if opts.Signer == nil {
		panic("service.New: Signer is required")
	}
	if opts.Revocations == nil {
		panic("service.New: Revocations is required")
	}
	if opts.Secret == "" {
		panic("service.New: Secret is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	ttl := opts.TokenTTL
	if ttl <= 0 {
		ttl = defaultTokenTTL
	}
	return &service{
		store:       opts.Store,
		secret:      opts.Secret,
		signer:      opts.Signer,
		revocations: opts.Revocations,
		audit:       opts.Audit,
		tokenTTL:    ttl,
		logger:      logger,
	}
}

func (s *service) Enroll(ctx context.Context, req api.EnrollRequest, sourceIP string) (api.EnrollResponse, error) {
	if req.EnrollSecret == "" || req.HardwareUUID == "" || req.Hostname == "" ||
		req.OSVersion == "" || req.AgentVersion == "" {
		// The handler maps this to 400/bad_body via the missing-field check it already does. Service returns ErrInvalidSecret only if
		// the secret is non-empty but wrong; an empty secret is a body-shape error.
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
	// Register's REPLACE INTO reset the row to a clean state (epoch 0, not revoked), so the host mints at epoch 0. Evict it from this
	// replica's revocation snapshot so the token we are about to mint verifies immediately here, instead of being rejected by a stale
	// snapshot (still showing the pre-re-enroll epoch / revoked state) for up to the refresh interval: the transient-401-after-re-enroll
	// race. Other replicas converge on their next refresh.
	s.revocations.Forget(res.HostID)
	now := time.Now().UTC()
	token, exp, err := s.signer.Mint(res.HostID, 0, s.tokenTTL, now)
	if err != nil {
		return api.EnrollResponse{}, fmt.Errorf("mint host token: %w", err)
	}
	return api.EnrollResponse{
		HostID:     res.HostID,
		HostToken:  token,
		EnrolledAt: res.EnrolledAt,
		ExpiresAt:  exp,
	}, nil
}

// VerifyToken is the agent hot path: a local HMAC signature + expiry check (no DB), then an in-memory revocation lookup. Every failure
// mode collapses to ErrInvalidToken so the wire cannot distinguish "expired" from "forged" from "revoked" (that would be an oracle).
func (s *service) VerifyToken(_ context.Context, token string) (string, error) {
	claims, err := s.signer.Verify(token, time.Now())
	if err != nil {
		return "", api.ErrInvalidToken
	}
	if !s.revocations.Allowed(claims.HostID, claims.Epoch) {
		return "", api.ErrInvalidToken
	}
	return claims.HostID, nil
}

// RefreshToken issues a fresh token for the host_id pinned on the context by the host-token middleware. The agent calls this before its
// current token expires so a live host never lapses. It is not the hot path (once per token lifetime per host), so a single DB read for
// the host's current epoch + revocation state is acceptable; minting at the current epoch keeps the new token valid against the
// revocation snapshot. A revoked or unknown host gets ErrInvalidToken, which the handler maps to 401 -> the agent re-enrolls.
func (s *service) RefreshToken(ctx context.Context, token string) (api.RefreshResponse, error) {
	// Re-verify the presented token (cheap; refresh is not the hot path) so we can compare ITS epoch to the host's current DB epoch.
	// The host-token middleware gates this route using the per-replica revocation snapshot, which is eventually consistent, so during
	// the staleness window a pre-rotate (stale-epoch) token can still pass the middleware. Without this check, refresh would then mint
	// a fresh token at the current (bumped) epoch and let the stale token survive an operator credential cycle. Rejecting a presented
	// epoch below the current epoch closes that window authoritatively against the DB.
	claims, err := s.signer.Verify(token, time.Now())
	if err != nil {
		return api.RefreshResponse{}, api.ErrInvalidToken
	}
	epoch, revoked, err := s.store.TokenStatus(ctx, claims.HostID)
	if errors.Is(err, mysql.ErrNotFound) {
		return api.RefreshResponse{}, api.ErrInvalidToken
	}
	if err != nil {
		return api.RefreshResponse{}, fmt.Errorf("refresh token status: %w", err)
	}
	if revoked || claims.Epoch < epoch {
		return api.RefreshResponse{}, api.ErrInvalidToken
	}
	now := time.Now().UTC()
	newToken, exp, err := s.signer.Mint(claims.HostID, epoch, s.tokenTTL, now)
	if err != nil {
		return api.RefreshResponse{}, fmt.Errorf("mint refresh token: %w", err)
	}
	return api.RefreshResponse{HostID: claims.HostID, HostToken: newToken, ExpiresAt: exp}, nil
}

// RotateToken cycles a host's credentials by bumping its token_epoch, which invalidates every signed token minted at the prior epoch
// once the revocation snapshot picks up the change. There is no opaque token to rotate and no command to push: the agent recovers by
// re-enrolling when its refresh (carrying the now-stale epoch) 401s. trigger/actor/reason feed the audit row. Returns ErrNotFound when
// the host has no enrollment.
func (s *service) RotateToken(ctx context.Context, hostID string, trigger api.RotationTrigger, actor, reason string) (api.RotateResult, error) {
	if hostID == "" {
		return api.RotateResult{}, fmt.Errorf("rotate token: %w", api.ErrNotFound)
	}
	if err := s.store.BumpTokenEpoch(ctx, hostID); err != nil {
		if errors.Is(err, mysql.ErrNotFound) {
			return api.RotateResult{}, api.ErrNotFound
		}
		return api.RotateResult{}, fmt.Errorf("rotate token: %w", err)
	}
	s.recordRotationAudit(ctx, hostID, trigger, actor, reason)
	// RotateResult carries no token or command under this model: the prefix + command_id fields stay zero, which the operator handler
	// already renders as "agent will recover via re-enroll".
	return api.RotateResult{}, nil
}

// recordRotationAudit emits one audit row for a credential-cycle. Best-effort: a missed audit row is a follow-up incident, not a reason
// to fail an HTTP response that already succeeded.
func (s *service) recordRotationAudit(ctx context.Context, hostID string, trigger api.RotationTrigger, actor, reason string) {
	if s.audit == nil {
		return
	}
	payload := map[string]any{"trigger": string(trigger)}
	if actor != "" {
		payload["actor"] = actor
	}
	if reason != "" {
		payload["reason"] = reason
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

// toAPIEnrollment is a struct-to-struct copy. Field shapes match exactly today (the api.Enrollment was lifted from the mysql row), so
// this is a pure relocation, but the conversion stays explicit so a future field drift between the storage layer and the public api
// surface forces a review here rather than slipping through.
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
