package bootstrap

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rulecontentapi "github.com/fleetdm/edr/server/rulecontent/api"
	"github.com/fleetdm/edr/server/rules/internal/catalog"
)

// fakeCorpus is a scripted rulecontent supplier.
//
// err applies to both reads, which is the shape of an unreachable store; versionErr narrows a failure to the version counter
// alone, so the reload path's two reads can fail independently. calls records each read in order when non-nil, which is how the
// version-before-documents ordering is asserted.
type fakeCorpus struct {
	docs       []rulecontentapi.Document
	err        error
	version    int64
	versionErr error
	calls      *[]string
}

func (f fakeCorpus) Documents(context.Context) ([]rulecontentapi.Document, error) {
	f.record("documents")
	return f.docs, f.err
}

func (f fakeCorpus) Version(context.Context) (int64, error) {
	f.record("version")
	if f.versionErr != nil {
		return 0, f.versionErr
	}
	return f.version, f.err
}

func (f fakeCorpus) record(op string) {
	if f.calls != nil {
		*f.calls = append(*f.calls, op)
	}
}

// embeddedCorpus presents the vendored corpus as storage-shaped documents, so the good case exercises the real parse path over
// the same content the seed would have written rather than a fixture that only resembles it.
func embeddedCorpus(t *testing.T) []rulecontentapi.Document {
	t.Helper()
	src := EmbeddedCorpusFS()
	var docs []rulecontentapi.Document
	require.NoError(t, fs.WalkDir(src, EmbeddedCorpusRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, readErr := fs.ReadFile(src, path)
		if readErr != nil {
			return readErr
		}
		docs = append(docs, rulecontentapi.Document{Path: path, Content: body})
		return nil
	}))
	require.NotEmpty(t, docs)
	return docs
}

// capturingHandler records only whether anything was logged at WARN or above, which is the whole assertion here.
type capturingHandler struct{ warned bool }

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		h.warned = true
	}
	return nil
}

func (h *capturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(string) slog.Handler      { return h }

// spec:rule-content/an-unavailable-or-unusable-store-leaves-detections-running/a-system-starting-up-has-no-running-set-to-keep
// spec:rule-content/an-unavailable-or-unusable-store-leaves-detections-running/an-unseeded-store-is-not-an-error
// spec:rule-content/an-unavailable-or-unusable-store-leaves-detections-running/content-that-fails-to-load-does-not-stop-detection
//
// TestLoadCorpus_FallsBackRatherThanRunningNoRules covers the acceptance criterion that a storage problem must not cost the
// detections themselves.
//
// At construction there is no previous good set to keep, so the build's own corpus IS the previous good set, and it is the same
// content the seed would have written. That makes falling back strictly better than failing: the deployment behaves as it did
// before rule content was stored, rather than starting blind because a database was briefly unreachable.
//
// The empty case is separated from the failure case on purpose. An unseeded store is the expected state on a first boot, so
// reporting it as a problem would train an operator to ignore the line that matters.
func TestLoadCorpus_FallsBackRatherThanRunningNoRules(t *testing.T) {
	t.Parallel()

	embedded := len(catalog.MustLoadImported())
	require.Positive(t, embedded, "a corpus of zero rules would make every assertion here vacuous")

	cases := []struct {
		name      string
		corpus    rulecontentapi.Corpus
		wantWarn  bool
		wantRules int
	}{
		{
			name:      "no supplier wired at all",
			corpus:    nil,
			wantWarn:  false,
			wantRules: embedded,
		},
		{
			name:      "store unreachable",
			corpus:    fakeCorpus{err: errors.New("dial tcp: connection refused")},
			wantWarn:  true,
			wantRules: embedded,
		},
		{
			name:      "store empty, which is a first boot and not a problem",
			corpus:    fakeCorpus{docs: nil},
			wantWarn:  false,
			wantRules: embedded,
		},
		{
			name:      "content present but unparseable",
			corpus:    fakeCorpus{docs: []rulecontentapi.Document{{Path: "imported/broken.yml", Content: []byte("{{ not sigma")}}},
			wantWarn:  true,
			wantRules: embedded,
		},
		{
			// This row was missing, and its absence is why the path shipped wrong: documents that the loader refuses ONE BY ONE
			// come back as success with an empty set, not as an error, so a deployment whose stored corpus is entirely unrunnable
			// started with no corpus detections at all while the empty-store row above fell back. The two are the same determinate
			// state and have to reach the same rule set. A file_event rule is the real refusal this sensor produces.
			name: "content present and every document refused",
			corpus: fakeCorpus{docs: []rulecontentapi.Document{{
				Path:    "imported/file_event/file_event_macos_emond_launch_daemon.yml",
				Content: mustReadEmbedded(t, "imported/file_event/file_event_macos_emond_launch_daemon.yml"),
			}}},
			wantWarn:  true,
			wantRules: embedded,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var logged capturingHandler
			rules := loadCorpus(t.Context(), tc.corpus, slog.New(&logged))

			assert.Len(t, rules, tc.wantRules, "the build's corpus must still be evaluated")
			assert.Equal(t, tc.wantWarn, logged.warned,
				"a fallback for a reason is reported; an unseeded store is not, because it is the expected first-boot state")
		})
	}

	t.Run("stored content is used when it loads", func(t *testing.T) {
		t.Parallel()
		var logged capturingHandler
		rules := loadCorpus(t.Context(), fakeCorpus{docs: embeddedCorpus(t)}, slog.New(&logged))

		assert.Len(t, rules, embedded, "the stored corpus is the vendored one here, so it must yield the same rules")
		assert.False(t, logged.warned, "and loading successfully is not a fallback")
	})
}
