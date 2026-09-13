package watchedpaths

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/appcontrol"
)

// ErrReasonRequired is returned for a change without a reason. Every change is audited with its reason, and a blank one would leave
// the audit row saying nothing about why the fleet started watching different files.
var ErrReasonRequired = errors.New("watchedpaths: reason is required")

// Service stores the watched-path set and pushes it to hosts.
type Service struct {
	store    *Store
	commands appcontrol.CommandBatchInserter
	hosts    appcontrol.HostLister
	audit    identityapi.AuditRecorder
	logger   *slog.Logger
	now      func() time.Time
}

// NewService builds a Service. store, commands and hosts are required; audit may be nil outside production, which logs each change
// that goes unaudited.
func NewService(store *Store, commands appcontrol.CommandBatchInserter, hosts appcontrol.HostLister, audit identityapi.AuditRecorder,
	logger *slog.Logger) *Service {
	if store == nil || commands == nil || hosts == nil {
		panic("watchedpaths.NewService: store, commands and hosts are required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{store: store, commands: commands, hosts: hosts, audit: audit, logger: logger, now: time.Now}
}

// Get returns the stored set.
func (s *Service) Get(ctx context.Context) (api.WatchedPathSet, error) {
	return s.store.Get(ctx)
}

// ReplaceResult is a replaced set and how its push to hosts went.
type ReplaceResult struct {
	Set api.WatchedPathSet `json:"set"`
	// FanoutHosts is how many enrolled hosts the set was queued for, and FanoutFailed how many of those it could not be queued for.
	FanoutHosts  int `json:"fanout_hosts"`
	FanoutFailed int `json:"fanout_failed"`
}

// Replace validates paths, stores them as the new set, queues a set_watched_paths command for every enrolled host, and audits the
// change with its reason.
//
// The stored set is authoritative once written, so a push that does not reach every host does not fail the change: the result counts
// the hosts it missed, and so does the audit row.
func (s *Service) Replace(ctx context.Context, actor *identityapi.Actor, reason string, paths []api.WatchedPath) (ReplaceResult, error) {
	if strings.TrimSpace(reason) == "" {
		return ReplaceResult{}, ErrReasonRequired
	}
	if err := api.ValidateWatchedPaths(paths); err != nil {
		return ReplaceResult{}, err
	}
	if paths == nil {
		// A request that omits the list is an empty set, stored as an empty JSON array so a read never returns null.
		paths = []api.WatchedPath{}
	}
	previous, err := s.store.Get(ctx)
	if err != nil {
		return ReplaceResult{}, err
	}
	set, err := s.store.Replace(ctx, paths, actor.Principal.ID, s.now())
	if err != nil {
		return ReplaceResult{}, err
	}
	attempted, failed := s.fanout(ctx, set)
	s.recordAudit(ctx, actor, reason, previous, set, attempted, failed)
	return ReplaceResult{Set: set, FanoutHosts: attempted, FanoutFailed: failed}, nil
}

// fanout queues the set for every enrolled host in one batched insert and returns how many hosts it tried and how many it missed.
func (s *Service) fanout(ctx context.Context, set api.WatchedPathSet) (attempted, failed int) {
	// A replaced set always carries its update time, which Replace just wrote.
	payload, err := json.Marshal(api.SetWatchedPathsPayload{Version: set.Version, Epoch: set.UpdatedAt.UnixMicro(), Paths: set.Paths})
	if err != nil {
		// Unreachable for a slice of string fields, but a set that cannot be encoded reached no host.
		s.logger.ErrorContext(ctx, "watchedpaths: encode command payload", "err", err)
		return 0, 0
	}
	hostIDs, err := s.hosts(ctx)
	if err != nil {
		s.logger.WarnContext(ctx, "watchedpaths: host list failed; set not pushed", "version", set.Version, "err", err)
		return 0, 0
	}
	if len(hostIDs) == 0 {
		return 0, 0
	}
	hostIDs = slices.Clone(hostIDs)
	slices.Sort(hostIDs)
	inserted, err := s.commands(ctx, hostIDs, api.CommandTypeSetWatchedPaths, payload)
	failed = len(hostIDs) - inserted
	if err != nil {
		s.logger.WarnContext(ctx, "watchedpaths: queueing the set failed for some hosts",
			"version", set.Version, "attempted", len(hostIDs), "inserted", inserted, "err", err)
	}
	return len(hostIDs), failed
}

func (s *Service) recordAudit(ctx context.Context, actor *identityapi.Actor, reason string, previous, set api.WatchedPathSet,
	attempted, failed int) {
	event := identityapi.AuditEvent{
		Actor:      actor.Principal,
		Action:     identityapi.AuditDetectionConfigWatchedPathsUpdate,
		TargetType: "watched_path_set",
		TargetID:   strconv.FormatInt(set.Version, 10),
		Payload: map[string]any{
			"reason":           reason,
			"version":          set.Version,
			"paths":            set.Paths,
			"previous_version": previous.Version,
			"previous_paths":   previous.Paths,
			"fanout_hosts":     attempted,
			"fanout_failed":    failed,
		},
	}
	if s.audit == nil {
		s.logger.WarnContext(ctx, "watchedpaths: audit recorder not configured; change not audited", "version", set.Version)
		return
	}
	if err := s.audit.Record(ctx, event); err != nil {
		s.logger.WarnContext(ctx, "watchedpaths: audit record failed", "version", set.Version, "err", err)
	}
}
