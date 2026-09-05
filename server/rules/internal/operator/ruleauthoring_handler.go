package operator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	rulecontentapi "github.com/fleetdm/edr/server/rulecontent/api"
	"github.com/fleetdm/edr/server/rules/internal/ruleauthoring"
)

// ruleContentBodyLimit bounds a request body for this surface.
//
// Comfortably above the 64 KiB a single document may hold, because the body carries the content plus a JSON envelope and a
// reason, and a limit that cut into legal content would present as a mysterious failure at a size nothing documents. The
// document bound itself is the validator's to enforce, and it does, with a message naming the size.
const ruleContentBodyLimit = 256 * 1024

const (
	errCodeRCInvalidJSON  = "rule_content.invalid_json"
	errCodeRCReadBody     = "rule_content.read_body"
	errCodeRCBodyTooLarge = "rule_content.body_too_large"
	errCodeRCInvalidInput = "rule_content.invalid_input"
	errCodeRCRefused      = "rule_content.refused"
	errCodeRCNotFound     = "rule_content.not_found"
	errCodeRCConflict     = "rule_content.conflict"
	errCodeRCInternal     = "internal"

	msgRCInternal = "internal error"
)

// ruleAuthoringService is the narrow surface this handler consumes; *ruleauthoring.Service satisfies it. An interface so handler
// tests can drive the success and failure branches without a corpus, a validator, or a database.
type ruleAuthoringService interface {
	Put(ctx context.Context, actor *identityapi.Actor, reason string, doc rulecontentapi.Document) (int64, []string, error)
	Delete(ctx context.Context, actor *identityapi.Actor, reason string, path string) (int64, []string, error)
	Check(ctx context.Context, doc rulecontentapi.Document) ([]string, error)
}

// ruleContentCorpus is the read side, held separately because reading and changing are separately authorized.
type ruleContentCorpus interface {
	Documents(ctx context.Context) ([]rulecontentapi.Document, error)
	Version(ctx context.Context) (int64, error)
}

// RuleAuthoringHandler serves the /api/v1/rule-content/* routes: the rule documents a deployment loads, as opposed to the per-rule
// tuning the DetectionConfigHandler beside it serves (issue #767).
//
// It lives in this package rather than in rulecontent, which is the question ADR-0021 deferred to #767. Authoring shares the
// tuning surface's authorization chokepoint, audit recorder, handler shell and error envelope, and shares its screen: an operator
// authors a rule and then sets its mode from the table next to it. A handler in rulecontent would mean a second copy of all of
// that to serve a page beside one that already exists.
type RuleAuthoringHandler struct {
	svc    ruleAuthoringService
	corpus ruleContentCorpus
	authz  identityapi.AuthZ
	logger *slog.Logger
}

// NewRuleAuthoringHandler builds the handler. A nil service or corpus is an error rather than a handler that 500s per request:
// this surface either exists or it does not, and a deployment that wired it wrong should fail to start.
func NewRuleAuthoringHandler(
	svc ruleAuthoringService, corpus ruleContentCorpus, authz identityapi.AuthZ, logger *slog.Logger,
) (*RuleAuthoringHandler, error) {
	if svc == nil || corpus == nil || authz == nil {
		return nil, errors.New("rule authoring handler: a service, a corpus and an authorizer are all required")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &RuleAuthoringHandler{svc: svc, corpus: corpus, authz: authz, logger: logger}, nil
}

// RegisterRoutes mounts the surface.
//
// The document path is a trailing wildcard because a rule path carries directories, so it contains slashes and is not a single
// segment. `{path...}` is what matches it; a plain `{path}` would 404 every real document.
func (h *RuleAuthoringHandler) RegisterRoutes(mux httpserver.Router) {
	mux.HandleFunc("GET /api/v1/rule-content/documents", h.handleList)
	mux.HandleFunc("POST /api/v1/rule-content/documents:check", h.handleCheck)
	mux.HandleFunc("GET /api/v1/rule-content/documents/{path...}", h.handleGet)
	mux.HandleFunc("PUT /api/v1/rule-content/documents/{path...}", h.handlePut)
	mux.HandleFunc("DELETE /api/v1/rule-content/documents/{path...}", h.handleDelete)
}

type documentSummary struct {
	Path  string `json:"path"`
	Bytes int    `json:"bytes"`
}

// handleList returns the corpus as summaries plus its version.
//
// Summaries rather than content, because the corpus is every rule a deployment runs and returning all of it to render a list
// would send megabytes to draw a table of names. The per-document GET below serves content.
func (h *RuleAuthoringHandler) handleList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionRuleContentRead, identityapi.Resource{Type: "rule_content"}) {
		return
	}
	version, err := h.corpus.Version(ctx)
	if err != nil {
		h.internal(ctx, w, "read corpus version", err)
		return
	}
	docs, err := h.corpus.Documents(ctx)
	if err != nil {
		h.internal(ctx, w, "read corpus", err)
		return
	}
	out := make([]documentSummary, 0, len(docs))
	for _, d := range docs {
		out = append(out, documentSummary{Path: d.Path, Bytes: len(d.Content)})
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, map[string]any{"corpus_version": version, "documents": out})
}

// handleGet returns one document's content verbatim.
//
// Served as the rule file itself rather than wrapped in JSON, for the reason the rule export endpoint is: the response IS the
// artifact an operator edits and hands to another tool, and a caller who has to unwrap it first is worse off.
func (h *RuleAuthoringHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionRuleContentRead, identityapi.Resource{Type: "rule_content"}) {
		return
	}
	docs, err := h.corpus.Documents(ctx)
	if err != nil {
		h.internal(ctx, w, "read corpus", err)
		return
	}
	wanted := r.PathValue("path")
	for _, d := range docs {
		if d.Path == wanted {
			w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			if _, werr := w.Write(d.Content); werr != nil {
				h.logger.WarnContext(ctx, "rule content: write response failed", "err", werr, "document", wanted)
			}
			return
		}
	}
	writeOperatorErr(ctx, h.logger, w, http.StatusNotFound, errCodeRCNotFound, "no such rule document")
}

type putDocumentRequest struct {
	Content string `json:"content"`
	Reason  string `json:"reason"`
}

// handlePut creates or replaces a document.
func (h *RuleAuthoringHandler) handlePut(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionRuleContentWrite, identityapi.Resource{Type: "rule_content"}) {
		return
	}
	var req putDocumentRequest
	if !h.decode(ctx, w, r, &req) {
		return
	}
	actor, ok := h.actor(ctx, w)
	if !ok {
		return
	}
	doc := rulecontentapi.Document{Path: r.PathValue("path"), Content: []byte(req.Content)}
	version, warnings, err := h.svc.Put(ctx, actor, req.Reason, doc)
	if err != nil {
		h.writeChangeErr(ctx, w, "put rule document", err)
		return
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, map[string]any{
		"path": doc.Path, "corpus_version": version, "warnings": nonNilWarnings(warnings),
	})
}

type deleteDocumentRequest struct {
	Reason string `json:"reason"`
}

// handleDelete removes a document.
func (h *RuleAuthoringHandler) handleDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionRuleContentWrite, identityapi.Resource{Type: "rule_content"}) {
		return
	}
	var req deleteDocumentRequest
	if !h.decode(ctx, w, r, &req) {
		return
	}
	actor, ok := h.actor(ctx, w)
	if !ok {
		return
	}
	path := r.PathValue("path")
	version, warnings, err := h.svc.Delete(ctx, actor, req.Reason, path)
	if err != nil {
		h.writeChangeErr(ctx, w, "delete rule document", err)
		return
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, map[string]any{
		"path": path, "corpus_version": version, "warnings": nonNilWarnings(warnings),
	})
}

type checkDocumentRequest struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// handleCheck reports what submitting a document would do, without doing it.
//
// A refusal comes back as 200 with `would_apply: false`, not as a 4xx, and the distinction is deliberate. The CHECK succeeded:
// the operator asked a question and got a correct answer. A 4xx would say the request was wrong, which it was not, and would
// force a caller to treat "your rule has a problem" and "your request was malformed" through the same branch.
//
// Gated on READ rather than write, because it changes nothing. An operator who may see what the deployment detects may also ask
// whether a change would be accepted.
func (h *RuleAuthoringHandler) handleCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionRuleContentRead, identityapi.Resource{Type: "rule_content"}) {
		return
	}
	var req checkDocumentRequest
	if !h.decode(ctx, w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Path) == "" {
		writeOperatorErr(ctx, h.logger, w, http.StatusBadRequest, errCodeRCInvalidInput, "path is required")
		return
	}
	warnings, err := h.svc.Check(ctx, rulecontentapi.Document{Path: req.Path, Content: []byte(req.Content)})
	body := map[string]any{"would_apply": err == nil, "warnings": nonNilWarnings(warnings)}
	if err != nil {
		body["refusal"] = err.Error()
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, body)
}

// nonNilWarnings keeps the field an array in JSON rather than null, so a caller can iterate it without a nil check.
func nonNilWarnings(w []string) []string {
	if w == nil {
		return []string{}
	}
	return w
}

// writeChangeErr maps a change failure to the status that describes it.
func (h *RuleAuthoringHandler) writeChangeErr(ctx context.Context, w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, ruleauthoring.ErrReasonRequired):
		writeOperatorErr(ctx, h.logger, w, http.StatusBadRequest, errCodeRCInvalidInput, err.Error())
	case errors.Is(err, rulecontentapi.ErrRefused):
		// 422 rather than 400: the request was well formed and the content was not, which is the distinction a caller needs to
		// decide whether to fix its own call or show the operator a rule problem.
		writeOperatorErr(ctx, h.logger, w, http.StatusUnprocessableEntity, errCodeRCRefused, err.Error())
	case errors.Is(err, rulecontentapi.ErrDocumentNotFound):
		writeOperatorErr(ctx, h.logger, w, http.StatusNotFound, errCodeRCNotFound, "no such rule document")
	case errors.Is(err, rulecontentapi.ErrCorpusChanged):
		// 409, and the message says to retry, because that is the whole remedy: the corpus moved between validation and the
		// write, so the same change against the current corpus is very likely to succeed.
		writeOperatorErr(ctx, h.logger, w, http.StatusConflict, errCodeRCConflict,
			"the rule corpus changed while this was being validated; re-read it and try again")
	default:
		h.internal(ctx, w, op, err)
	}
}

func (h *RuleAuthoringHandler) internal(ctx context.Context, w http.ResponseWriter, op string, err error) {
	h.logger.ErrorContext(ctx, "rule content handler: "+op+" failed", "err", err)
	writeOperatorErr(ctx, h.logger, w, http.StatusInternalServerError, errCodeRCInternal, msgRCInternal)
}

func (h *RuleAuthoringHandler) actor(ctx context.Context, w http.ResponseWriter) (*identityapi.Actor, bool) {
	actor, ok := identityapi.ActorFromContext(ctx)
	if !ok {
		h.logger.ErrorContext(ctx, "rule content handler: no actor on ctx despite session middleware")
		writeOperatorErr(ctx, h.logger, w, http.StatusInternalServerError, errCodeRCInternal, msgRCInternal)
		return nil, false
	}
	return actor, true
}

// decode reads a bounded JSON body into v.
func (h *RuleAuthoringHandler) decode(ctx context.Context, w http.ResponseWriter, r *http.Request, v any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, ruleContentBodyLimit))
	if err != nil {
		if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
			writeOperatorErr(ctx, h.logger, w, http.StatusRequestEntityTooLarge, errCodeRCBodyTooLarge,
				"request body is too large")
			return false
		}
		writeOperatorErr(ctx, h.logger, w, http.StatusBadRequest, errCodeRCReadBody, "could not read request body")
		return false
	}
	if err := json.Unmarshal(body, v); err != nil {
		writeOperatorErr(ctx, h.logger, w, http.StatusBadRequest, errCodeRCInvalidJSON, "request body is not valid JSON")
		return false
	}
	return true
}
