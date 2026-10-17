package operator

import (
	"context"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// ActivityReader is the activity rollup read surface (issue #1285): what a set of process generations touched, from the archive, and
// the one process a process scope names, read by its row id.
type ActivityReader interface {
	ActivityForGenerations(ctx context.Context, filter visibilityapi.ActivityFilter) (visibilityapi.ActivityRollup, error)
	GetProcessByID(ctx context.Context, hostID string, id int64) (*api.Process, error)
	SessionTouches(ctx context.Context, hostID string, generation visibilityapi.ProcessGeneration) ([]visibilityapi.SessionTouch, error)
}

// SetActivity installs the activity read surface. Bootstrap wires it with the detection store in ModeFull; unset, the route answers
// 503.
func (h *Handler) SetActivity(r ActivityReader) { h.activity = r }

func (h *Handler) registerActivityRoutes(mux httpserver.Router) {
	mux.HandleFunc("GET /api/hosts/{host_id}/activity", h.handleActivity)
}

// activityProcess names a process of the scope, so a client can say which process touched each artifact: rows carry the (pid,
// pidversion) they were matched by, and this maps it to the process's row and image.
type activityProcess struct {
	ID         int64  `json:"id"`
	PID        int    `json:"pid"`
	PIDVersion uint32 `json:"pidversion"`
	Path       string `json:"path"`
}

// activityResponse is the rollup with the report of how far the scope reached and the scope's processes.
type activityResponse struct {
	visibilityapi.ActivityRollup
	Scope     timelineScope     `json:"scope"`
	Processes []activityProcess `json:"processes"`
}

// activityScopeRequest is the scope ?scope= names: one process or its whole subtree by the process's row id, or a story or session
// as the tree reads them.
type activityScopeRequest struct {
	process int64
	subtree bool
	tree    api.TreeScope
}

// parseActivityScope reads ?scope=process|subtree&process=<id>, ?scope=session&session=<id> or ?scope=story&root=<id>. A scope is
// required: without one there is nothing to total.
func parseActivityScope(q url.Values) (activityScopeRequest, bool) {
	switch q.Get("scope") {
	case "process", "subtree":
		id, err := strconv.ParseInt(q.Get("process"), 10, 64)
		return activityScopeRequest{process: id, subtree: q.Get("scope") == "subtree"}, err == nil && id > 0
	}
	tree, scoped, valid := parseTreeScope(q)
	return activityScopeRequest{tree: tree}, scoped && valid
}

func (h *Handler) handleActivity(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := r.PathValue("host_id")
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, identityapi.ActionProcessRead, identityapi.Resource{Type: "process", ID: hostID}) {
		return
	}
	if h.activity == nil {
		h.writeError(ctx, w, http.StatusServiceUnavailable, errInternal)
		return
	}
	req, ok := parseActivityScope(r.URL.Query())
	if !ok {
		h.writeError(ctx, w, http.StatusBadRequest, errInvalidScope)
		return
	}
	roots, agents, truncated, err := h.activityScopeProcesses(ctx, hostID, req)
	if err != nil {
		h.logger.ErrorContext(ctx, "resolve activity scope", "host_id", hostID, "err", err)
		h.writeError(ctx, w, http.StatusInternalServerError, errInternal)
		return
	}
	generations, scope, matched := scopeGenerations(roots, truncated)
	filter := visibilityapi.ActivityFilter{HostID: hostID, Generations: generations}
	if req.tree.AgentSessionID != "" {
		if filter, err = h.boundAgents(ctx, req.tree.AgentSessionID, agents, filter); err != nil {
			h.logger.ErrorContext(ctx, "bound agent activity", "host_id", hostID, "err", err)
			h.writeError(ctx, w, http.StatusInternalServerError, errInternal)
			return
		}
	}
	// A scope with no generation to match is answered with nothing, not with the host's whole activity: the totals would claim the
	// scope touched what other processes did.
	rollup, err := h.activity.ActivityForGenerations(ctx, filter)
	if err != nil {
		h.logger.ErrorContext(ctx, "activity rollup", "host_id", hostID, "err", err)
		h.writeError(ctx, w, http.StatusInternalServerError, errInternal)
		return
	}
	processes := make([]activityProcess, 0, len(matched))
	for _, n := range matched {
		processes = append(processes, activityProcess{ID: n.ID, PID: n.PID, PIDVersion: *n.PIDVersion, Path: n.Path})
	}
	h.writeJSON(w, r, activityResponse{ActivityRollup: rollup, Scope: *scope, Processes: processes})
}

// activityScopeProcesses reads the scope's processes. A process alone is read by its row id. Its subtree is read from the chain
// pinned at it, whose descendants come from the story index (issue #1282), and cut at the pinned process: its ancestors did not do
// what the process did. For a session it also returns the agent processes it added to the session's own, which lead the roots: a
// scope over the generation cap is cut from its tail, and the agent, whose Read, Edit and Write run inside it, must not be what goes.
func (h *Handler) activityScopeProcesses(
	ctx context.Context, hostID string, req activityScopeRequest,
) (roots, agents []api.ProcessNode, truncated bool, err error) {
	switch {
	case req.process == 0:
		res, err := h.svc.BuildScopedTree(ctx, hostID, req.tree, maxTimelineChain, true, 0)
		if err != nil || req.tree.AgentSessionID == "" {
			return res.Roots, nil, res.Truncated, err
		}
		agents, err := h.sessionAgents(ctx, hostID, req.tree.AgentSessionID, res.Roots)
		return append(slices.Clone(agents), res.Roots...), agents, res.Truncated, err
	case !req.subtree:
		proc, err := h.activity.GetProcessByID(ctx, hostID, req.process)
		if err != nil || proc == nil {
			return nil, nil, false, err
		}
		return []api.ProcessNode{{Process: *proc}}, nil, false, nil
	}
	res, err := h.svc.BuildChainTree(ctx, hostID, api.TimeRange{ToNs: math.MaxInt64}, req.process, true)
	if err != nil {
		return nil, nil, false, err
	}
	pinned := findProcessNode(res.Roots, req.process)
	if pinned == nil {
		return nil, nil, false, nil
	}
	return []api.ProcessNode{*pinned}, nil, res.Truncated, nil
}

// sessionAgents returns the agent process of a session's processes (issue #1287): the creator of a tool call's root whose pid is the
// one the session's CLAUDE_PID marker names. The agent carries no session marker of its own, so the session read never holds it, yet
// Claude Code's Read, Edit and Write run inside it. Its activity is that of its whole life, which spans only this session unless the
// agent switched sessions in one process.
func (h *Handler) sessionAgents(ctx context.Context, hostID, sessionID string, roots []api.ProcessNode) ([]api.ProcessNode, error) {
	if h.agentSessions == nil {
		return nil, nil
	}
	session, err := h.agentSessions.GetAgentSession(ctx, hostID, sessionID)
	if err != nil || session == nil || session.AgentPID == nil {
		return nil, err
	}
	agentPID := *session.AgentPID
	var agents []api.ProcessNode
	read := map[int64]bool{}
	for _, root := range roots {
		creator := root.ParentProcessID
		if creator == nil || read[*creator] {
			continue
		}
		read[*creator] = true
		proc, err := h.activity.GetProcessByID(ctx, hostID, *creator)
		if err != nil {
			return nil, err
		}
		if proc != nil && proc.PID == agentPID {
			agents = append(agents, api.ProcessNode{Process: *proc})
		}
	}
	return agents, nil
}

// boundAgents bounds each of a session's agent processes, those sessionAgents found, to the span it served the session (issue #1319).
// One agent process can serve several sessions in turn (/clear), and its activity belongs to each only while it served it.
func (h *Handler) boundAgents(
	ctx context.Context, sessionID string, agents []api.ProcessNode, filter visibilityapi.ActivityFilter,
) (visibilityapi.ActivityFilter, error) {
	for _, agent := range agents {
		span, bounded, err := h.agentSpan(ctx, filter.HostID, sessionID, agent)
		if err != nil {
			return filter, err
		}
		if !bounded {
			continue
		}
		filter.Generations = slices.DeleteFunc(filter.Generations, func(g visibilityapi.ProcessGeneration) bool {
			return g == span.ProcessGeneration
		})
		filter.Spans = append(filter.Spans, span)
	}
	return filter, nil
}

// agentSpan is the span an agent process served a session, from the session transcripts its generation touched (issue #1319). It is
// not bounded when the process served no other session, or its generation is unknown: its whole life is then the session's.
func (h *Handler) agentSpan(
	ctx context.Context, hostID, sessionID string, agent api.ProcessNode,
) (visibilityapi.GenerationSpan, bool, error) {
	if agent.PIDVersion == nil {
		return visibilityapi.GenerationSpan{}, false, nil
	}
	gen := visibilityapi.ProcessGeneration{PID: int64(agent.PID), PIDVersion: int64(*agent.PIDVersion)}
	touches, err := h.activity.SessionTouches(ctx, hostID, gen)
	if err != nil {
		return visibilityapi.GenerationSpan{}, false, err
	}
	span, bounded := sessionSpan(touches, sessionID)
	span.ProcessGeneration = gen
	return span, bounded, nil
}

// agentWindow is the window an agent process's own processes are listed for in a session (issue #1361): the span it served the
// session, or its whole life when it served only this one. The tree read and the alert read both use it, so they list the same.
func (h *Handler) agentWindow(ctx context.Context, hostID, sessionID string, agent api.ProcessNode) (int64, int64, error) {
	span, bounded, err := h.agentSpan(ctx, hostID, sessionID, agent)
	if err != nil {
		return 0, 0, err
	}
	fromNs, toNs := int64(0), int64(math.MaxInt64)
	if bounded {
		fromNs = span.FromNs
		if span.ToNs > 0 {
			toNs = span.ToNs
		}
	}
	return fromNs, toNs, nil
}

// agentOwnProcesses sets each of a session's agent processes' Children to its own processes (issue #1361): what it ran for itself,
// with no session marker, while it served the session. It reports whether any agent's were cut at their bound.
func (h *Handler) agentOwnProcesses(ctx context.Context, hostID, sessionID string, agents []api.ProcessNode) (bool, error) {
	cut := false
	for i := range agents {
		fromNs, toNs, err := h.agentWindow(ctx, hostID, sessionID, agents[i])
		if err != nil {
			return false, err
		}
		own, truncated, err := h.svc.BuildAgentOwnTree(ctx, hostID, agents[i].ID, fromNs, toNs)
		if err != nil {
			return false, err
		}
		agents[i].Children = own
		cut = cut || truncated
	}
	return cut, nil
}

// sessionSpan is the span an agent process served a session, from the transcripts it touched: from its first touch of the session's
// transcript (the process's start, for the first session it served) to its first touch of a later session's. It is not bounded when
// the process touched no other session's transcript, or never touched this one's, which leaves nothing to bound it by.
func sessionSpan(touches []visibilityapi.SessionTouch, sessionID string) (visibilityapi.GenerationSpan, bool) {
	own := slices.IndexFunc(touches, func(t visibilityapi.SessionTouch) bool { return t.SessionID == sessionID })
	if own < 0 || len(touches) < 2 {
		return visibilityapi.GenerationSpan{}, false
	}
	var span visibilityapi.GenerationSpan
	for _, t := range touches {
		switch {
		case t.SessionID == sessionID:
		case t.FirstNs < touches[own].FirstNs:
			span.FromNs = touches[own].FirstNs
		case span.ToNs == 0 || t.FirstNs < span.ToNs:
			span.ToNs = t.FirstNs
		}
	}
	return span, true
}

// findProcessNode returns the node of the process with the given row id, or nil when the forest does not hold it.
func findProcessNode(nodes []api.ProcessNode, id int64) *api.ProcessNode {
	for i := range nodes {
		if nodes[i].ID == id {
			return &nodes[i]
		}
		if found := findProcessNode(nodes[i].Children, id); found != nil {
			return found
		}
	}
	return nil
}
