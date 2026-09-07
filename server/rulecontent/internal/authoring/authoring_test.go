package authoring

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rulecontent/api"
)

// fakeCorpus is the corpus in force.
type fakeCorpus struct {
	docs       []api.Document
	version    int64
	err        error
	versionErr error
}

func (f *fakeCorpus) Documents(context.Context) ([]api.Document, error) { return f.docs, f.err }
func (f *fakeCorpus) Version(context.Context) (int64, error)            { return f.version, f.versionErr }

// fakeWriter records what it was asked to write, so a test can assert that a refusal wrote NOTHING rather than only that it
// returned an error.
type fakeWriter struct {
	put      []api.Document
	deleted  []string
	expected []int64
	err      error
}

func (f *fakeWriter) PutDocument(_ context.Context, doc api.Document, expected int64) (int64, error) {
	f.put = append(f.put, doc)
	f.expected = append(f.expected, expected)
	return 7, f.err
}

func (f *fakeWriter) DeleteDocument(_ context.Context, path string, expected int64) (int64, error) {
	f.deleted = append(f.deleted, path)
	f.expected = append(f.expected, expected)
	return 8, f.err
}

// fakeValidator captures the document set it was asked about, which is the property most of these tests are really about.
type fakeValidator struct {
	saw      []api.Document
	warnings []api.ContentWarning
	err      error
}

func (f *fakeValidator) Validate(_ context.Context, docs []api.Document) ([]api.ContentWarning, error) {
	f.saw = docs
	return f.warnings, f.err
}

func newService(t *testing.T, corpus *fakeCorpus, w *fakeWriter, v *fakeValidator) *Service {
	t.Helper()
	s, err := New(corpus, w, v)
	require.NoError(t, err)
	return s
}

func pathsOf(docs []api.Document) []string {
	out := make([]string, 0, len(docs))
	for _, d := range docs {
		out = append(out, d.Path)
	}
	return out
}

// TestPut_ValidatesTheWholeProposedCorpus is the property the whole design turns on.
//
// A rule's identity is its file stem, and the loader treats two documents claiming one identity as an error refusing the ENTIRE
// corpus. So a validator shown only the submitted document would accept the one write that can drop a deployment to the rule set
// embedded in its binary. What it must see is the corpus the write would produce.
func TestPut_ValidatesTheWholeProposedCorpus(t *testing.T) {
	t.Parallel()
	corpus := &fakeCorpus{docs: []api.Document{
		{Path: "imported/a.yml", Content: []byte("a")},
		{Path: "imported/b.yml", Content: []byte("b")},
	}}
	v := &fakeValidator{}
	w := &fakeWriter{}

	_, _, err := newService(t, corpus, w, v).Put(t.Context(), api.Document{Path: "authored/c.yml", Content: []byte("c")})
	require.NoError(t, err)

	assert.Equal(t, []string{"authored/c.yml", "imported/a.yml", "imported/b.yml"}, pathsOf(v.saw),
		"the validator must see the corpus the write would produce, not the submitted document alone")
}

// TestPut_ReplacingSubstitutesRatherThanAppends pins that editing an existing path does not present the validator with two
// documents claiming one identity, which would make every edit look like a collision.
func TestPut_ReplacingSubstitutesRatherThanAppends(t *testing.T) {
	t.Parallel()
	corpus := &fakeCorpus{docs: []api.Document{{Path: "imported/a.yml", Content: []byte("old")}}}
	v := &fakeValidator{}

	_, _, err := newService(t, corpus, &fakeWriter{}, v).Put(t.Context(),
		api.Document{Path: "imported/a.yml", Content: []byte("new")})
	require.NoError(t, err)

	require.Len(t, v.saw, 1, "replacing a path must not present the corpus with two documents at it")
	assert.Equal(t, "new", string(v.saw[0].Content), "and the validator must see the NEW content, not what is stored")
}

// spec:rule-content/authored-content-is-validated-by-the-loader/a-document-the-loader-refuses-is-not-written
//
// TestPut_RefusedWritesNothing checks both halves, and the second is the one worth asserting explicitly: a test that only checked
// the error would pass even if the document had been written first and the error returned afterwards.
func TestPut_RefusedWritesNothing(t *testing.T) {
	t.Parallel()
	w := &fakeWriter{}
	v := &fakeValidator{err: errors.New("rule id \"a\" is already claimed by imported/a.yml")}

	_, _, err := newService(t, &fakeCorpus{}, w, v).Put(t.Context(), api.Document{Path: "authored/a.yml"})

	require.Error(t, err)
	require.ErrorIs(t, err, api.ErrRefused, "callers branch on this")
	assert.Contains(t, err.Error(), "already claimed by imported/a.yml",
		"the validator's own reason must survive, since it is what names the thing to fix")
	assert.Empty(t, w.put, "a refused document must not reach the store")
}

// TestPut_WarningsDoNotBlockTheWrite pins the foot-gun posture: advisory findings are reported, not enforced.
func TestPut_WarningsDoNotBlockTheWrite(t *testing.T) {
	t.Parallel()
	w := &fakeWriter{}
	v := &fakeValidator{warnings: []api.ContentWarning{
		{Path: "authored/a.yml", Message: "authored/a.yml will not run: unsupported field"},
	}}

	version, warnings, err := newService(t, &fakeCorpus{}, w, v).Put(t.Context(), api.Document{Path: "authored/a.yml"})

	require.NoError(t, err)
	assert.Equal(t, int64(7), version)
	assert.Equal(t, []api.ContentWarning{
		{Path: "authored/a.yml", Message: "authored/a.yml will not run: unsupported field"},
	}, warnings)
	assert.Len(t, w.put, 1, "a warning is advice, not a refusal")
}

// TestDelete_ValidatesWhatWouldRemain covers the less obvious half of validating deletes: removing a rule can be the change that
// breaks a corpus, because what is left still has to load.
func TestDelete_ValidatesWhatWouldRemain(t *testing.T) {
	t.Parallel()
	corpus := &fakeCorpus{docs: []api.Document{
		{Path: "imported/a.yml"}, {Path: "imported/b.yml"},
	}}
	v := &fakeValidator{}
	w := &fakeWriter{}

	_, _, err := newService(t, corpus, w, v).Delete(t.Context(), "imported/a.yml")
	require.NoError(t, err)

	assert.Equal(t, []string{"imported/b.yml"}, pathsOf(v.saw))
	assert.Equal(t, []string{"imported/a.yml"}, w.deleted)
}

// TestDelete_NotFoundIsRefusedBeforeValidating pins that a delete of something absent neither validates a corpus nobody proposed
// nor reaches the store, where it would otherwise be caught only after the version had a chance to move.
func TestDelete_NotFoundIsRefusedBeforeValidating(t *testing.T) {
	t.Parallel()
	corpus := &fakeCorpus{docs: []api.Document{{Path: "imported/a.yml"}}}
	v := &fakeValidator{}
	w := &fakeWriter{}

	_, _, err := newService(t, corpus, w, v).Delete(t.Context(), "imported/never-existed.yml")

	require.Error(t, err)
	require.ErrorIs(t, err, api.ErrDocumentNotFound)
	assert.Nil(t, v.saw, "nothing was proposed, so there is nothing to validate")
	assert.Empty(t, w.deleted)
}

// TestNew_RequiresEveryDependency keeps "validated" a property of the type rather than of the wiring. A Service constructible
// without a validator would put the trust boundary at the mercy of whichever caller assembles it next.
func TestNew_RequiresEveryDependency(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		corpus api.Corpus
		writer api.Writer
		valid  api.Validator
	}{
		"no corpus":    {nil, &fakeWriter{}, &fakeValidator{}},
		"no writer":    {&fakeCorpus{}, nil, &fakeValidator{}},
		"no validator": {&fakeCorpus{}, &fakeWriter{}, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := New(tc.corpus, tc.writer, tc.valid)
			assert.Error(t, err)
		})
	}
}

// TestPut_UnreadableCorpusRefusesRatherThanValidatingAPartialSet pins that a corpus we could not read is not silently treated as
// an empty one, which would validate the submitted document against nothing and hide every collision.
func TestPut_UnreadableCorpusRefusesRatherThanValidatingAPartialSet(t *testing.T) {
	t.Parallel()
	v := &fakeValidator{}
	w := &fakeWriter{}
	corpus := &fakeCorpus{err: errors.New("connection refused")}

	_, _, err := newService(t, corpus, w, v).Put(t.Context(), api.Document{Path: "authored/a.yml"})

	require.Error(t, err)
	assert.Nil(t, v.saw, "validating against a corpus we failed to read would hide every collision in it")
	assert.Empty(t, w.put)
}

// TestPut_WritesAgainstTheVersionItValidated is what stops validation being advisory under concurrency.
//
// Validating a snapshot and then writing in a separate transaction is a check-then-act. Two operators adding authored/x.yml and
// other/x.yml at the same moment each validate against a corpus without the other, both pass, and the corpus that lands claims one
// rule identity twice. Every replica then refuses the whole thing and falls back to the copy embedded in its binary, which is the
// exact failure whole-corpus validation exists to prevent.
//
// The write therefore carries the version the validation was done against, and the store refuses if the corpus has moved.
func TestPut_WritesAgainstTheVersionItValidated(t *testing.T) {
	t.Parallel()
	w := &fakeWriter{}
	corpus := &fakeCorpus{version: 42, docs: []api.Document{{Path: "imported/a.yml"}}}

	_, _, err := newService(t, corpus, w, &fakeValidator{}).Put(t.Context(), api.Document{Path: "authored/b.yml"})
	require.NoError(t, err)

	require.Equal(t, []int64{42}, w.expected, "the write must be conditional on the version that was validated")
}

// TestDelete_WritesAgainstTheVersionItValidated is the same property for the other mutation.
func TestDelete_WritesAgainstTheVersionItValidated(t *testing.T) {
	t.Parallel()
	w := &fakeWriter{}
	corpus := &fakeCorpus{version: 9, docs: []api.Document{{Path: "imported/a.yml"}, {Path: "imported/b.yml"}}}

	_, _, err := newService(t, corpus, w, &fakeValidator{}).Delete(t.Context(), "imported/a.yml")
	require.NoError(t, err)

	require.Equal(t, []int64{9}, w.expected)
}

// TestPut_UnreadableVersionRefusesBeforeReadingDocuments pins that a version we could not read is not silently treated as zero,
// which would make every write claim to have validated against the corpus's very first state.
func TestPut_UnreadableVersionRefusesBeforeReadingDocuments(t *testing.T) {
	t.Parallel()
	w := &fakeWriter{}
	v := &fakeValidator{}
	corpus := &fakeCorpus{versionErr: errors.New("connection refused")}

	_, _, err := newService(t, corpus, w, v).Put(t.Context(), api.Document{Path: "authored/a.yml"})

	require.Error(t, err)
	assert.Nil(t, v.saw)
	assert.Empty(t, w.put)
}

// spec:rule-content/a-change-is-told-only-about-itself/a-write-reports-only-findings-about-the-document-written
//
// TestPut_ReportsOnlyWarningsAboutTheDocumentBeingWritten is the fix for #876, and the assertion that matters is the ABSENCE of
// the other warning.
//
// Validation is corpus-wide by design, so the validator reports findings about every document in the proposed set. Passing all of
// them back meant an operator writing one rule was told about files they never touched and could not fix, and worse, the caller
// records warnings on the audit row, so a reviewer reading the row for one change saw findings about documents it was not about.
//
// A governance surface that misattributes is worse than a noisy one, which is why this is a test rather than a nicety.
func TestPut_ReportsOnlyWarningsAboutTheDocumentBeingWritten(t *testing.T) {
	t.Parallel()
	w := &fakeWriter{}
	v := &fakeValidator{warnings: []api.ContentWarning{
		{Path: "imported/pre_existing.yml", Message: "imported/pre_existing.yml will not run: unsupported field"},
		{Path: "authored/mine.yml", Message: "mine: search \"selection\" discriminates nothing"},
	}}

	_, warnings, err := newService(t, &fakeCorpus{}, w, v).Put(t.Context(), api.Document{Path: "authored/mine.yml"})
	require.NoError(t, err)

	require.Len(t, warnings, 1, "only the finding about this document belongs to this change")
	assert.Equal(t, "authored/mine.yml", warnings[0].Path)
	assert.NotContains(t, warnings[0].Message, "pre_existing",
		"a finding about a document the operator did not touch must not be attributed to their change")
}

// spec:rule-content/a-change-is-told-only-about-itself/a-deletion-reports-no-findings-about-the-document-removed
//
// TestDelete_ReportsNoWarningsAboutADocumentThatIsGone pins the delete side of the same narrowing. The proposed corpus no longer
// contains the path, so nothing in the findings is about it, and that is the correct answer rather than a degenerate one: a
// deletion that BREAKS the corpus is an error, not a warning.
func TestDelete_ReportsNoWarningsAboutADocumentThatIsGone(t *testing.T) {
	t.Parallel()
	corpus := &fakeCorpus{docs: []api.Document{{Path: "authored/mine.yml"}, {Path: "imported/other.yml"}}}
	v := &fakeValidator{warnings: []api.ContentWarning{
		{Path: "imported/other.yml", Message: "imported/other.yml will not run: unsupported field"},
	}}

	_, warnings, err := newService(t, corpus, &fakeWriter{}, v).Delete(t.Context(), "authored/mine.yml")
	require.NoError(t, err)

	assert.Empty(t, warnings, "a pre-existing finding about another document is not a result of this deletion")
}
