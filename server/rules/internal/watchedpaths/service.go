package watchedpaths

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strconv"
	"strings"

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
	return &Service{store: store, commands: commands, hosts: hosts, audit: audit, logger: logger}
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
	// FanoutSkippedReason says why the set was queued for no host when that was a failure rather than an empty fleet:
	// appcontrol.FanoutSkipReasonHostLister when the enrolled hosts could not be listed. Empty otherwise.
	FanoutSkippedReason string `json:"fanout_skipped_reason,omitempty"`
}

// Replace validates paths, stores them as the new set, queues a set_watched_paths command for every enrolled host, and audits the
// change with its reason.
//
// The stored set is authoritative once written, so a push that does not reach every host does not fail the change: the result counts
// the hosts it missed, and so does the audit row.
//
// A non-nil expectedVersion is the version the caller's edit started from; the change is refused with ErrVersionConflict when the set
// has moved on, so a stale edit cannot silently remove paths someone else added.
func (s *Service) Replace(
	ctx context.Context, actor *identityapi.Actor, reason string, paths []api.WatchedPath, expectedVersion *int64,
) (ReplaceResult, error) {
	if strings.TrimSpace(reason) == "" {
		return ReplaceResult{}, ErrReasonRequired
	}
	if err := api.ValidateWatchedPaths(paths); err != nil {
		return ReplaceResult{}, err
	}
	previous, set, err := s.store.Replace(ctx, paths, actor.Principal.ID, expectedVersion)
	if err != nil {
		return ReplaceResult{}, err
	}
	result := s.fanout(ctx, set)
	s.recordAudit(ctx, actor, reason, previous, result)
	return result, nil
}

// commandPayload is the set_watched_paths payload for a stored set. The push and the catch-up both build it here, so a host that is
// caught up gets exactly what the push sent. The set must have been changed at least once, so it carries its update time. Marshalling
// a struct of strings and integers cannot fail.
func commandPayload(set api.WatchedPathSet) []byte {
	payload, _ := json.Marshal(api.SetWatchedPathsPayload{Version: set.Version, Epoch: set.UpdatedAt.UnixMicro(), Paths: set.Paths})
	return payload
}

// fanout queues the set for every enrolled host in one batched insert and reports how many hosts it tried, how many it missed, and
// why it reached none when that was a failure.
func (s *Service) fanout(ctx context.Context, set api.WatchedPathSet) ReplaceResult {
	result := ReplaceResult{Set: set}
	hostIDs, err := s.hosts(ctx)
	if err != nil {
		s.logger.WarnContext(ctx, "watchedpaths: host list failed; set not pushed", "version", set.Version, "err", err)
		result.FanoutSkippedReason = appcontrol.FanoutSkipReasonHostLister
		return result
	}
	if len(hostIDs) == 0 {
		return result
	}
	payload := commandPayload(set)
	hostIDs = slices.Clone(hostIDs)
	slices.Sort(hostIDs)
	inserted, err := s.commands(ctx, hostIDs, api.CommandTypeSetWatchedPaths, payload)
	result.FanoutHosts, result.FanoutFailed = len(hostIDs), len(hostIDs)-inserted
	if err != nil {
		s.logger.WarnContext(ctx, "watchedpaths: queueing the set failed for some hosts",
			"version", set.Version, "attempted", len(hostIDs), "inserted", inserted, "err", err)
	}
	return result
}

func (s *Service) recordAudit(
	ctx context.Context, actor *identityapi.Actor, reason string, previous api.WatchedPathSet, result ReplaceResult,
) {
	set := result.Set
	payload := map[string]any{
		"reason":           reason,
		"version":          set.Version,
		"paths":            set.Paths,
		"previous_version": previous.Version,
		"previous_paths":   previous.Paths,
		"fanout_hosts":     result.FanoutHosts,
		"fanout_failed":    result.FanoutFailed,
	}
	if result.FanoutSkippedReason != "" {
		payload["fanout_skipped_reason"] = result.FanoutSkippedReason
	}
	event := identityapi.AuditEvent{
		Actor:      actor.Principal,
		Action:     identityapi.AuditDetectionConfigWatchedPathsUpdate,
		TargetType: "watched_path_set",
		TargetID:   strconv.FormatInt(set.Version, 10),
		Payload:    payload,
	}
	if s.audit == nil {
		s.logger.WarnContext(ctx, "watchedpaths: audit recorder not configured; change not audited", "version", set.Version)
		return
	}
	if err := s.audit.Record(ctx, event); err != nil {
		s.logger.WarnContext(ctx, "watchedpaths: audit record failed", "version", set.Version, "err", err)
	}
}
