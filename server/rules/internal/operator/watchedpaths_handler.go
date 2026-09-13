package operator

import (
	"context"
	"errors"
	"net/http"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/watchedpaths"
)

// watchedPathsService is the watched-path surface the detection-config handler consumes; *watchedpaths.Service satisfies it.
type watchedPathsService interface {
	Get(ctx context.Context) (api.WatchedPathSet, error)
	Replace(ctx context.Context, actor *identityapi.Actor, reason string, paths []api.WatchedPath, expectedVersion *int64) (
		watchedpaths.ReplaceResult, error)
}

// watchedPathsResponse is the GET body: the stored set, the paths every host watches regardless of it, and the size bound, so a client
// can say what is always watched and how much room is left without restating either.
type watchedPathsResponse struct {
	api.WatchedPathSet
	BuiltIn  []api.WatchedPath `json:"built_in"`
	MaxPaths int               `json:"max_paths"`
}

// replaceWatchedPathsRequest is the PUT body. Paths is a pointer so a request without it is refused rather than read as an empty set:
// a client that misspells the field would otherwise remove every path an operator had added. Clearing the set is an explicit
// empty list.
//
// ExpectedVersion, when present, is the version the client's edit started from, and the replacement is refused with 409 when the set
// has changed since. Optional, so a script that means to overwrite whatever is stored still can.
type replaceWatchedPathsRequest struct {
	Paths           *[]api.WatchedPath `json:"paths"`
	Reason          string             `json:"reason"`
	ExpectedVersion *int64             `json:"expected_version"`
}

// watchedPathsBodyLimit caps the PUT body. It is sized from the largest set the API accepts rather than shared with the other
// detection-config routes: a set is at most api.MaxWatchedPathSetBytes as the server encodes it, a client may escape every byte of it
// as a six-byte \uXXXX sequence, and a reason rides along, so a cap below that would refuse a valid set with a 413 before validation
// saw it.
const watchedPathsBodyLimit = 6*api.MaxWatchedPathSetBytes + 16*1024

// msgWatchedPathsRequired is the refusal for a PUT without a paths list.
const msgWatchedPathsRequired = "paths is required; send an empty list to stop watching every path added"

// SetWatchedPaths wires the watched-path routes (issue #998). Set after construction, and only where the command queue and the
// enrolled-host list the push needs are wired.
func (h *DetectionConfigHandler) SetWatchedPaths(svc watchedPathsService) {
	h.watchedPaths = svc
}

func (h *DetectionConfigHandler) handleGetWatchedPaths(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionDetectionConfigRead, identityapi.Resource{Type: "detection_config"}) {
		return
	}
	set, err := h.watchedPaths.Get(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "detectionconfig get watched paths", "err", err)
		writeDetectionConfigErr(ctx, h.logger, w, http.StatusInternalServerError, errCodeDCInternal, msgDCInternal)
		return
	}
	h.resolveUpdatedByLabel(ctx, &set)
	writeJSON(ctx, h.logger, w, http.StatusOK, watchedPathsResponse{
		WatchedPathSet: set, BuiltIn: api.BuiltInWatchedPaths, MaxPaths: api.MaxWatchedPaths,
	})
}

func (h *DetectionConfigHandler) handleReplaceWatchedPaths(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionDetectionConfigWrite, identityapi.Resource{Type: "detection_config"}) {
		return
	}
	var req replaceWatchedPathsRequest
	if !h.decodeCapped(ctx, w, r, &req, watchedPathsBodyLimit) {
		return
	}
	if req.Paths == nil {
		writeDetectionConfigErr(ctx, h.logger, w, http.StatusBadRequest, errCodeDCInvalidInput, msgWatchedPathsRequired)
		return
	}
	actor, ok := h.actor(ctx, w)
	if !ok {
		return
	}
	result, err := h.watchedPaths.Replace(ctx, actor, req.Reason, *req.Paths, req.ExpectedVersion)
	switch {
	case errors.Is(err, watchedpaths.ErrVersionConflict):
		writeDetectionConfigErr(ctx, h.logger, w, http.StatusConflict, errCodeDCConflict, err.Error())
	case errors.Is(err, watchedpaths.ErrReasonRequired):
		writeDetectionConfigErr(ctx, h.logger, w, http.StatusBadRequest, errCodeDCInvalidInput, msgDCReasonRequired)
	case errors.Is(err, api.ErrInvalidWatchedPaths):
		writeDetectionConfigErr(ctx, h.logger, w, http.StatusBadRequest, errCodeDCInvalidInput, err.Error())
	case err != nil:
		h.logger.ErrorContext(ctx, "detectionconfig replace watched paths", "err", err)
		writeDetectionConfigErr(ctx, h.logger, w, http.StatusInternalServerError, errCodeDCInternal, msgDCInternal)
	default:
		h.resolveUpdatedByLabel(ctx, &result.Set)
		writeJSON(ctx, h.logger, w, http.StatusOK, result)
	}
}

// resolveUpdatedByLabel fills the set's UpdatedByLabel from its UpdatedBy, so the console can say who last changed the set by name.
// The set no operator has changed has no UpdatedBy and gets no label.
func (h *DetectionConfigHandler) resolveUpdatedByLabel(ctx context.Context, set *api.WatchedPathSet) {
	if h.principalLabel == nil || set.UpdatedBy == "" {
		return
	}
	set.UpdatedByLabel = h.resolveLabel(ctx, set.UpdatedBy)
}
