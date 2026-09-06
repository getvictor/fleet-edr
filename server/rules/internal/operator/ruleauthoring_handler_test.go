package operator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	rulecontentapi "github.com/fleetdm/edr/server/rulecontent/api"
	"github.com/fleetdm/edr/server/rules/internal/ruleauthoring"
)

// readOnlyAuthZ allows reads of rule content and denies changes, which is the band senior_analyst actually holds. A blanket
// allow-all or deny-all fake cannot express it, and it is the case the surface is split for.
type readOnlyAuthZ struct{}

func (readOnlyAuthZ) Allow(_ context.Context, a identityapi.Action, _ identityapi.Resource) (identityapi.Decision, error) {
	if a == identityapi.ActionRuleContentRead {
		return identityapi.Decision{Allow: true, Reason: "granted"}, nil
	}
	return identityapi.Decision{Allow: false, Reason: "no_matching_rule"}, nil
}

type fakeAuthoringSvc struct {
	putErr    error
	deleteErr error
	checkErr  error
	warnings  []string
	puts      []rulecontentapi.Document
	deletes   []string
	reasons   []string
}

func (f *fakeAuthoringSvc) Put(
	_ context.Context, _ *identityapi.Actor, reason string, doc rulecontentapi.Document,
) (int64, []string, error) {
	f.reasons = append(f.reasons, reason)
	if f.putErr != nil {
		return 0, nil, f.putErr
	}
	f.puts = append(f.puts, doc)
	return 3, f.warnings, nil
}

func (f *fakeAuthoringSvc) Delete(
	_ context.Context, _ *identityapi.Actor, reason string, path string,
) (int64, []string, error) {
	f.reasons = append(f.reasons, reason)
	if f.deleteErr != nil {
		return 0, nil, f.deleteErr
	}
	f.deletes = append(f.deletes, path)
	return 4, f.warnings, nil
}

func (f *fakeAuthoringSvc) Check(_ context.Context, _ rulecontentapi.Document) ([]string, error) {
	return f.warnings, f.checkErr
}

type fakeRCCorpus struct {
	docs []rulecontentapi.Document
	err  error
}

func (f fakeRCCorpus) Documents(context.Context) ([]rulecontentapi.Document, error) {
	return f.docs, f.err
}
func (f fakeRCCorpus) Version(context.Context) (int64, error) { return 5, f.err }

func rcServer(t *testing.T, svc ruleAuthoringService, corpus ruleContentCorpus, authz identityapi.AuthZ) *httptest.Server {
	t.Helper()
	h, err := NewRuleAuthoringHandler(svc, corpus, &fakeRCPacks{}, authz, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := identityapi.WithActor(r.Context(),
			&identityapi.Actor{Principal: identityapi.UserPrincipal(7, ""), SessionFresh: true})
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func rcDo(t *testing.T, srv *httptest.Server, method, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, strings.NewReader(body))
	require.NoError(t, err)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(b)
}

// spec:rule-content/operators-reach-authoring-through-a-governed-surface/an-operator-without-write-permission-cannot-change-rule-content
//
// TestRuleAuthoring_ReadPermissionDoesNotGrantWrite is why the surface has two actions rather than one. senior_analyst is meant to
// see what the deployment detects without being able to change it, and a single action could not express that.
// fakeRCPacks is a stub pack lifecycle for the handler tests.
type fakeRCPacks struct {
	status    rulecontentapi.PackStatus
	statusErr error
	rolled    rulecontentapi.PackRollback
	rollErr   error
	reason    string
}

func (f *fakeRCPacks) Status(context.Context) (rulecontentapi.PackStatus, error) {
	return f.status, f.statusErr
}

func (f *fakeRCPacks) Rollback(_ context.Context, _ *identityapi.Actor, reason string) (rulecontentapi.PackRollback, error) {
	f.reason = reason
	return f.rolled, f.rollErr
}

func TestRuleAuthoring_ReadPermissionDoesNotGrantWrite(t *testing.T) {
	t.Parallel()
	svc := &fakeAuthoringSvc{}
	srv := rcServer(t, svc, fakeRCCorpus{}, readOnlyAuthZ{})

	readStatus, _ := rcDo(t, srv, http.MethodGet, "/api/v1/rule-content/documents", "")
	assert.Equal(t, http.StatusOK, readStatus, "reading is permitted for this band")

	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPut, "/api/v1/rule-content/documents/authored/a.yml", `{"content":"title: x\n","reason":"r"}`},
		{http.MethodDelete, "/api/v1/rule-content/documents/authored/a.yml", `{"reason":"r"}`},
	} {
		status, _ := rcDo(t, srv, tc.method, tc.path, tc.body)
		assert.Equal(t, http.StatusForbidden, status, "%s must be denied", tc.method)
	}
	assert.Empty(t, svc.puts, "a denied request must not reach the service")
	assert.Empty(t, svc.deletes)
}

// spec:rule-content/operators-reach-authoring-through-a-governed-surface/an-operator-without-read-permission-cannot-see-rule-content
func TestRuleAuthoring_DenyAllBlocksReads(t *testing.T) {
	t.Parallel()
	corpus := fakeRCCorpus{docs: []rulecontentapi.Document{{Path: "imported/a.yml", Content: []byte("a")}}}
	srv := rcServer(t, &fakeAuthoringSvc{}, corpus, denyAllAuthZ{})

	for _, path := range []string{"/api/v1/rule-content/documents", "/api/v1/rule-content/documents/imported/a.yml"} {
		status, _ := rcDo(t, srv, http.MethodGet, path, "")
		assert.Equal(t, http.StatusForbidden, status, "%s must be denied", path)
	}
}

// spec:rule-content/operators-reach-authoring-through-a-governed-surface/a-refusal-does-not-disclose-whether-the-document-exists
//
// TestRuleAuthoring_DenialDoesNotDiscloseExistence pins an ordering, not a message. Authorization runs before anything is looked
// up, so an unauthorized caller gets the same answer whether or not the document is there. Existence is itself information about
// what a deployment detects, and a surface that leaked it would let an unauthorized caller enumerate the corpus by probing.
func TestRuleAuthoring_DenialDoesNotDiscloseExistence(t *testing.T) {
	t.Parallel()
	corpus := fakeRCCorpus{docs: []rulecontentapi.Document{{Path: "imported/present.yml", Content: []byte("a")}}}
	srv := rcServer(t, &fakeAuthoringSvc{}, corpus, denyAllAuthZ{})

	presentStatus, presentBody := rcDo(t, srv, http.MethodGet, "/api/v1/rule-content/documents/imported/present.yml", "")
	absentStatus, absentBody := rcDo(t, srv, http.MethodGet, "/api/v1/rule-content/documents/imported/absent.yml", "")

	assert.Equal(t, presentStatus, absentStatus, "the status must not depend on whether the document exists")
	assert.Equal(t, presentBody, absentBody, "and neither must the body")
	assert.Equal(t, http.StatusForbidden, presentStatus)
}

// TestRuleAuthoring_ChangeErrorsMapToStatus covers the mapping an API client branches on. Each of these means something different
// to a caller, and collapsing them would leave a UI unable to tell "fix your rule" from "retry" from "we broke".
func TestRuleAuthoring_ChangeErrorsMapToStatus(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		err  error
		want int
	}{
		"validation refused":   {rulecontentapi.ErrRefused, http.StatusUnprocessableEntity},
		"no such document":     {rulecontentapi.ErrDocumentNotFound, http.StatusNotFound},
		"corpus moved":         {rulecontentapi.ErrCorpusChanged, http.StatusConflict},
		"no reason given":      {ruleauthoring.ErrReasonRequired, http.StatusBadRequest},
		"something unforeseen": {errors.New("connection refused"), http.StatusInternalServerError},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv := rcServer(t, &fakeAuthoringSvc{putErr: tc.err}, fakeRCCorpus{}, allowAllAuthZ{})
			status, body := rcDo(t, srv, http.MethodPut,
				"/api/v1/rule-content/documents/authored/a.yml", `{"content":"title: x\n","reason":"r"}`)
			assert.Equal(t, tc.want, status, "body=%s", body)
		})
	}
}

// TestRuleAuthoring_InternalErrorDoesNotLeakDetail keeps the 500 body free of the underlying failure, which for a store error can
// name schemas and hosts.
func TestRuleAuthoring_InternalErrorDoesNotLeakDetail(t *testing.T) {
	t.Parallel()
	srv := rcServer(t, &fakeAuthoringSvc{putErr: errors.New("dial tcp 10.1.2.3:3306: connection refused")},
		fakeRCCorpus{}, allowAllAuthZ{})

	status, body := rcDo(t, srv, http.MethodPut,
		"/api/v1/rule-content/documents/authored/a.yml", `{"content":"title: x\n","reason":"r"}`)

	require.Equal(t, http.StatusInternalServerError, status)
	assert.NotContains(t, body, "10.1.2.3", "an internal failure must not describe the deployment's internals")
	assert.NotContains(t, body, "3306")
}

// TestRuleAuthoring_PathWildcardCarriesDirectories pins the route shape. A rule path contains slashes, so a single-segment
// wildcard would 404 every real document, and the failure would look like a missing rule rather than a routing mistake.
func TestRuleAuthoring_PathWildcardCarriesDirectories(t *testing.T) {
	t.Parallel()
	svc := &fakeAuthoringSvc{}
	srv := rcServer(t, svc, fakeRCCorpus{}, allowAllAuthZ{})

	status, body := rcDo(t, srv, http.MethodPut,
		"/api/v1/rule-content/documents/imported/process_creation/deep_rule.yml", `{"content":"title: x\n","reason":"r"}`)

	require.Equal(t, http.StatusOK, status, body)
	require.Len(t, svc.puts, 1)
	assert.Equal(t, "imported/process_creation/deep_rule.yml", svc.puts[0].Path,
		"the whole path must reach the service, directories included")
}

// spec:rule-content/operators-can-check-content-before-publishing-it/a-check-reports-refusal-without-changing-anything
//
// TestRuleAuthoring_CheckReportsRefusalAsSuccess pins the status choice, which is the part a reviewer is most likely to question.
// The CHECK succeeded: the operator asked whether a change would be accepted and got a correct answer. A 4xx would say the
// request was wrong, which it was not, and would force a caller to treat "your rule has a problem" and "your request was
// malformed" through one branch.
func TestRuleAuthoring_CheckReportsRefusalAsSuccess(t *testing.T) {
	t.Parallel()
	srv := rcServer(t, &fakeAuthoringSvc{checkErr: errors.New("rule id \"x\" is already claimed")},
		fakeRCCorpus{}, allowAllAuthZ{})

	status, body := rcDo(t, srv, http.MethodPost, "/api/v1/rule-content/documents:check",
		`{"path":"authored/x.yml","content":"title: x\n"}`)

	require.Equal(t, http.StatusOK, status, "the question was answered, so the request succeeded")
	assert.Contains(t, body, `"would_apply":false`)
	assert.Contains(t, body, "already claimed", "and the reason survives, since it is what the operator fixes")
}

// TestRuleAuthoring_CheckNeedsOnlyRead pins that checking is gated on read. It changes nothing, so an operator permitted to see
// what the deployment detects may also ask whether a change would be accepted.
func TestRuleAuthoring_CheckNeedsOnlyRead(t *testing.T) {
	t.Parallel()
	srv := rcServer(t, &fakeAuthoringSvc{}, fakeRCCorpus{}, readOnlyAuthZ{})

	status, _ := rcDo(t, srv, http.MethodPost, "/api/v1/rule-content/documents:check",
		`{"path":"authored/x.yml","content":"title: x\n"}`)

	assert.Equal(t, http.StatusOK, status)
}

// TestRuleAuthoring_CheckRequiresAPath keeps a check from silently validating a pathless document, whose rule identity would be
// the empty string and whose answer would therefore be about nothing.
func TestRuleAuthoring_CheckRequiresAPath(t *testing.T) {
	t.Parallel()
	srv := rcServer(t, &fakeAuthoringSvc{}, fakeRCCorpus{}, allowAllAuthZ{})
	status, _ := rcDo(t, srv, http.MethodPost, "/api/v1/rule-content/documents:check", `{"content":"title: x\n"}`)
	assert.Equal(t, http.StatusBadRequest, status)
}

// TestRuleAuthoring_GetServesTheFileNotAnEnvelope pins that a document comes back as the artifact an operator edits, for the same
// reason the rule export endpoint does: a caller who must unwrap it first is worse off.
func TestRuleAuthoring_GetServesTheFileNotAnEnvelope(t *testing.T) {
	t.Parallel()
	corpus := fakeRCCorpus{docs: []rulecontentapi.Document{{Path: "imported/a.yml", Content: []byte("title: A Rule\n")}}}
	srv := rcServer(t, &fakeAuthoringSvc{}, corpus, allowAllAuthZ{})

	status, body := rcDo(t, srv, http.MethodGet, "/api/v1/rule-content/documents/imported/a.yml", "")

	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, "title: A Rule\n", body, "the response IS the rule file")
}

// TestRuleAuthoring_ListReportsSummariesNotContent keeps the listing from shipping every rule a deployment runs in order to draw
// a table of names.
func TestRuleAuthoring_ListReportsSummariesNotContent(t *testing.T) {
	t.Parallel()
	corpus := fakeRCCorpus{docs: []rulecontentapi.Document{
		{Path: "imported/a.yml", Content: []byte("title: A very long rule body\n")},
	}}
	srv := rcServer(t, &fakeAuthoringSvc{}, corpus, allowAllAuthZ{})

	status, body := rcDo(t, srv, http.MethodGet, "/api/v1/rule-content/documents", "")

	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, body, `"path":"imported/a.yml"`)
	assert.Contains(t, body, `"corpus_version":5`)
	assert.NotContains(t, body, "A very long rule body", "a listing must not carry every rule's content")
}

// TestRuleAuthoring_WarningsAreAlwaysAnArray keeps a caller from having to null-check before iterating.
func TestRuleAuthoring_WarningsAreAlwaysAnArray(t *testing.T) {
	t.Parallel()
	srv := rcServer(t, &fakeAuthoringSvc{}, fakeRCCorpus{}, allowAllAuthZ{})
	_, body := rcDo(t, srv, http.MethodPut,
		"/api/v1/rule-content/documents/authored/a.yml", `{"content":"title: x\n","reason":"r"}`)
	assert.Contains(t, body, `"warnings":[]`)
}

// TestRuleAuthoring_OversizeBodyIsRejected pins the 413 rather than a decode failure, so a caller sending too much learns that
// rather than being told its JSON is broken.
func TestRuleAuthoring_OversizeBodyIsRejected(t *testing.T) {
	t.Parallel()
	srv := rcServer(t, &fakeAuthoringSvc{}, fakeRCCorpus{}, allowAllAuthZ{})
	huge := `{"reason":"r","content":"` + strings.Repeat("p", ruleContentBodyLimit+1) + `"}`
	status, _ := rcDo(t, srv, http.MethodPut, "/api/v1/rule-content/documents/authored/a.yml", huge)
	assert.Equal(t, http.StatusRequestEntityTooLarge, status)
}

// TestNewRuleAuthoringHandler_RequiresItsCollaborators keeps a half-wired surface from starting. A handler that 500s on every
// request is worse than a route that is not mounted, because it looks available.
func TestNewRuleAuthoringHandler_RequiresItsCollaborators(t *testing.T) {
	t.Parallel()
	_, noSvc := NewRuleAuthoringHandler(nil, fakeRCCorpus{}, &fakeRCPacks{}, allowAllAuthZ{}, nil)
	require.Error(t, noSvc)
	_, noCorpus := NewRuleAuthoringHandler(&fakeAuthoringSvc{}, nil, &fakeRCPacks{}, allowAllAuthZ{}, nil)
	require.Error(t, noCorpus)
	_, noPacks := NewRuleAuthoringHandler(&fakeAuthoringSvc{}, fakeRCCorpus{}, nil, allowAllAuthZ{}, nil)
	require.Error(t, noPacks)
	_, noAuthz := NewRuleAuthoringHandler(&fakeAuthoringSvc{}, fakeRCCorpus{}, &fakeRCPacks{}, nil, nil)
	require.Error(t, noAuthz)
}

// rcServerWithActor is rcServer with a caller-supplied actor, so the actor SHAPE can be varied rather than assumed.
func rcServerWithActor(t *testing.T, svc ruleAuthoringService, actor *identityapi.Actor) *httptest.Server {
	t.Helper()
	h, err := NewRuleAuthoringHandler(svc, fakeRCCorpus{}, &fakeRCPacks{}, allowAllAuthZ{}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r.WithContext(identityapi.WithActor(r.Context(), actor)))
	})
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// TestRuleAuthoring_ServiceAccountWritesAreNotRejectedForActorShape is the #518 guard extended to this surface.
//
// A service account carries no human user id, and the bug that issue names was code that treated a missing user id as a missing
// actor and refused the write. Every new write route inherits that risk, and the existing table guarding it lives in a harness
// that cannot wire this surface, so the property is pinned here instead of being assumed to carry over.
func TestRuleAuthoring_ServiceAccountWritesAreNotRejectedForActorShape(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, method, path, body string }{
		{"put", http.MethodPut, "/api/v1/rule-content/documents/authored/sa.yml", `{"content":"title: x\n","reason":"ci push"}`},
		{"delete", http.MethodDelete, "/api/v1/rule-content/documents/authored/sa.yml", `{"reason":"ci cleanup"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// A service and server PER subtest. Sharing one across parallel subtests raced on the fake's recording slices, which
			// review caught: two handlers appending to the same slice is a data race under -race and can lose entries besides.
			srv := rcServerWithActor(t, &fakeAuthoringSvc{}, &identityapi.Actor{
				Principal:  identityapi.ServiceAccountPrincipal(7, "ci-bot"),
				AuthMethod: "service_account",
			})
			status, body := rcDo(t, srv, tc.method, tc.path, tc.body)
			assert.NotContains(t, body, "actor is required",
				"a service-account write must not be refused for carrying no human user id (#518)")
			assert.Equal(t, http.StatusOK, status, "body=%s", body)
		})
	}
}

// TestRuleAuthoring_MissingActorIsAnInternalErrorNotAnAnonymousChange pins the other side. If the session middleware ever stops
// putting an actor on the context, the change must NOT proceed unattributed: an unattributable mutation to what a fleet detects
// is worse than a failed one.
func TestRuleAuthoring_MissingActorIsAnInternalErrorNotAnAnonymousChange(t *testing.T) {
	t.Parallel()
	svc := &fakeAuthoringSvc{}
	h, err := NewRuleAuthoringHandler(svc, fakeRCCorpus{}, &fakeRCPacks{}, allowAllAuthZ{}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux) // no actor middleware at all
	t.Cleanup(srv.Close)

	status, _ := rcDo(t, srv, http.MethodPut,
		"/api/v1/rule-content/documents/authored/a.yml", `{"content":"title: x\n","reason":"r"}`)

	assert.Equal(t, http.StatusInternalServerError, status)
	assert.Empty(t, svc.puts, "an unattributable change must not reach the corpus")
}

// rcServerWithPacks is rcServer with a caller-supplied pack lifecycle, so the pack routes can be driven independently of the
// document ones they sit beside.
func rcServerWithPacks(t *testing.T, packs rulePackService) *httptest.Server {
	t.Helper()
	h, err := NewRuleAuthoringHandler(&fakeAuthoringSvc{}, fakeRCCorpus{}, packs, allowAllAuthZ{},
		slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	// An actor on the context, as the session middleware supplies in production. Without it the write route 500s before it
	// reaches the service, which is how the first version of these tests reported an internal error for every case.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := identityapi.WithActor(r.Context(),
			&identityapi.Actor{Principal: identityapi.UserPrincipal(7, ""), SessionFresh: true})
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// spec:rule-content/an-operator-can-see-and-restore-the-shipped-rule-content/an-operator-reads-which-shipped-rules-are-installed
//
// TestPackStatus_ReportsTheDifferenceAndWhetherRollbackIsPossible pins the wire shape an operator screen reads.
//
// `can_roll_back` is stated rather than left to be inferred from `previous`, because "can I undo this" is the question someone
// looking at a bad pack is actually asking, and making a caller derive it invites two surfaces deriving it differently.
func TestPackStatus_ReportsTheDifferenceAndWhetherRollbackIsPossible(t *testing.T) {
	t.Parallel()
	srv := rcServerWithPacks(t, &fakeRCPacks{status: rulecontentapi.PackStatus{
		Installed: "aaa", Available: "bbb", Previous: "old",
		Added: []string{"new_rule"}, Removed: []string{"gone_rule"}, Changed: []string{"edited_rule"},
	}})

	status, body := rcDo(t, srv, http.MethodGet, "/api/v1/rule-content/pack", "")
	require.Equal(t, http.StatusOK, status, body)

	var got struct {
		Installed   string   `json:"installed"`
		Available   string   `json:"available"`
		Current     bool     `json:"current"`
		CanRollBack bool     `json:"can_roll_back"`
		Added       []string `json:"added"`
		Removed     []string `json:"removed"`
		Changed     []string `json:"changed"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &got))
	assert.Equal(t, "aaa", got.Installed)
	assert.Equal(t, "bbb", got.Available)
	assert.False(t, got.Current, "the installed and available generations differ")
	assert.True(t, got.CanRollBack, "a previous generation is retained")
	assert.Equal(t, []string{"new_rule"}, got.Added)
	assert.Equal(t, []string{"gone_rule"}, got.Removed)
	assert.Equal(t, []string{"edited_rule"}, got.Changed)
}

// spec:rule-content/an-operator-can-see-and-restore-the-shipped-rule-content/a-restore-without-a-reason-is-refused
//
// TestPackRollback_RequiresAReason keeps the rollback on the same footing as every other change to rule content. This one is the
// strongest case for it: the change swaps out every shipped detection a deployment runs.
func TestPackRollback_RequiresAReason(t *testing.T) {
	t.Parallel()
	packs := &fakeRCPacks{rollErr: ruleauthoring.ErrReasonRequired}
	srv := rcServerWithPacks(t, packs)

	status, body := rcDo(t, srv, http.MethodPost, "/api/v1/rule-content/pack:rollback", `{"reason":"  "}`)
	assert.Equal(t, http.StatusBadRequest, status, body)
	assert.Contains(t, body, "reason is required")
}

// spec:rule-content/an-operator-can-see-and-restore-the-shipped-rule-content/a-restore-with-nothing-retained-is-refused-as-a-conflict
//
// TestPackRollback_WithNothingRetainedIsAConflict distinguishes "you asked for something that does not exist yet" from "something
// went wrong". A corpus that has never had a newer pack installed has nothing behind it, and a 500 would send an operator looking
// for a fault that is not there.
func TestPackRollback_WithNothingRetainedIsAConflict(t *testing.T) {
	t.Parallel()
	srv := rcServerWithPacks(t, &fakeRCPacks{rollErr: rulecontentapi.ErrNoPreviousPack})

	status, body := rcDo(t, srv, http.MethodPost, "/api/v1/rule-content/pack:rollback", `{"reason":"the new pack is too noisy"}`)
	assert.Equal(t, http.StatusConflict, status, body)
	assert.Contains(t, body, "nothing to roll back to")
}

// spec:rule-content/an-operator-can-see-and-restore-the-shipped-rule-content/a-restore-reports-what-it-withheld
//
// TestPackRollback_ReportsWhatItRestoredAndWithheld carries both halves back to the operator. The withheld list matters: the
// deployment is deliberately not running shipped rules it was offered, their own rule is why, and nothing else would say so.
func TestPackRollback_ReportsWhatItRestoredAndWithheld(t *testing.T) {
	t.Parallel()
	packs := &fakeRCPacks{rolled: rulecontentapi.PackRollback{
		Restored: "restored-digest", Version: 42, Withheld: []string{"imported/mine.yml"},
	}}
	srv := rcServerWithPacks(t, packs)

	status, body := rcDo(t, srv, http.MethodPost, "/api/v1/rule-content/pack:rollback", `{"reason":"rule X fires on everything"}`)
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, "rule X fires on everything", packs.reason, "the reason must reach the service that audits it")

	var got struct {
		Restored string   `json:"restored"`
		Version  int64    `json:"version"`
		Withheld []string `json:"withheld"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &got))
	assert.Equal(t, "restored-digest", got.Restored)
	assert.Equal(t, int64(42), got.Version)
	assert.Equal(t, []string{"imported/mine.yml"}, got.Withheld)
}

// TestPackStatus_EmptyDifferencesAreArraysNotNull pins the wire shape a consumer iterates.
//
// A nil slice marshals to `null`, which makes every reader null-check before iterating and makes "no rules changed" look like a
// missing field. Caught by reading the real response during QA rather than by a test, which is the argument for pinning it.
func TestPackStatus_EmptyDifferencesAreArraysNotNull(t *testing.T) {
	t.Parallel()
	srv := rcServerWithPacks(t, &fakeRCPacks{status: rulecontentapi.PackStatus{Installed: "same", Available: "same"}})

	status, body := rcDo(t, srv, http.MethodGet, "/api/v1/rule-content/pack", "")
	require.Equal(t, http.StatusOK, status, body)
	assert.Contains(t, body, `"added":[]`, "an empty difference list must be an array, not null")
	assert.Contains(t, body, `"removed":[]`)
	assert.Contains(t, body, `"changed":[]`)
	assert.NotContains(t, body, "null", "no field on this response should marshal to null")
}

// TestPackStatus_RoundTripsAnyDifferenceLists is the serialization invariant the project asks for on a new wire shape, over the
// input space a table cannot cover: any combination of rule identities in any of the three lists.
//
// The property is that what the handler emits decodes back to what it was given, with one deliberate exception stated as part of
// the property rather than worked around: a nil list comes back as an empty one, because the handler normalises it so consumers
// need no null check.
//
// It drives the handler through an httptest recorder rather than the shared server helpers, because rapid.T is neither a
// *testing.T nor a testing.TB and cannot be handed to them. Going through the recorder still exercises the real route and the
// real encoder, which is what the property is about.
func TestPackStatus_RoundTripsAnyDifferenceLists(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		ids := func(label string) []string {
			return rapid.SliceOfN(rapid.StringMatching(`[a-z_][a-z0-9_]{0,20}`), 0, 6).Draw(rt, label)
		}
		want := rulecontentapi.PackStatus{
			Installed: rapid.StringMatching(`[0-9a-f]{0,64}`).Draw(rt, "installed"),
			Available: rapid.StringMatching(`[0-9a-f]{0,64}`).Draw(rt, "available"),
			Previous:  rapid.StringMatching(`[0-9a-f]{0,64}`).Draw(rt, "previous"),
			Declined:  rapid.StringMatching(`[0-9a-f]{0,64}`).Draw(rt, "declined"),
			Added:     ids("added"),
			Removed:   ids("removed"),
			Changed:   ids("changed"),
		}

		h, err := NewRuleAuthoringHandler(&fakeAuthoringSvc{}, fakeRCCorpus{}, &fakeRCPacks{status: want},
			allowAllAuthZ{}, slog.New(slog.DiscardHandler))
		require.NoError(rt, err)
		mux := http.NewServeMux()
		h.RegisterRoutes(mux)

		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(
			identityapi.WithActor(context.Background(),
				&identityapi.Actor{Principal: identityapi.UserPrincipal(7, ""), SessionFresh: true}),
			http.MethodGet, "/api/v1/rule-content/pack", nil)
		mux.ServeHTTP(rec, req)
		require.Equal(rt, http.StatusOK, rec.Code, rec.Body.String())

		var got struct {
			Installed   string   `json:"installed"`
			Available   string   `json:"available"`
			Previous    string   `json:"previous"`
			Declined    string   `json:"declined"`
			Current     bool     `json:"current"`
			CanRollBack bool     `json:"can_roll_back"`
			Added       []string `json:"added"`
			Removed     []string `json:"removed"`
			Changed     []string `json:"changed"`
		}
		require.NoError(rt, json.Unmarshal(rec.Body.Bytes(), &got))

		assert.Equal(rt, want.Installed, got.Installed)
		assert.Equal(rt, want.Available, got.Available)
		assert.Equal(rt, want.Previous, got.Previous)
		assert.Equal(rt, want.Declined, got.Declined)
		assert.Equal(rt, want.Installed == want.Available, got.Current)
		assert.Equal(rt, want.Previous != "", got.CanRollBack)
		// Nil decodes as empty, which is the normalisation rather than a loss: as sequences the two are equal.
		assert.Equal(rt, orEmpty(want.Added), got.Added)
		assert.Equal(rt, orEmpty(want.Removed), got.Removed)
		assert.Equal(rt, orEmpty(want.Changed), got.Changed)
	})
}
