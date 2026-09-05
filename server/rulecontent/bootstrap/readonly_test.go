package bootstrap

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/rulecontent/api"
)

// spec:rule-content/the-read-surface-does-not-carry-the-write-surface/a-read-handle-cannot-be-converted-into-a-write-handle
//
// TestCorpus_DoesNotExposeTheWriteSurface closes a hole review found in the type system rather than in any line of logic.
//
// Returning the store directly, typed as api.Corpus, leaves the write methods on the dynamic type. Any consumer holding a Corpus
// could then type-assert to api.Writer, or to a local interface of the same shape, and persist content that never went through
// validation. Every guarantee the authoring path makes would hold only for callers that chose to use it.
//
// Asserted through a LOCAL interface as well as api.Writer, because a consumer inclined to reach past the published surface is
// exactly the one who would declare its own.
func TestCorpus_DoesNotExposeTheWriteSurface(t *testing.T) {
	t.Parallel()
	corpus := readOnlyCorpus{}

	_, isWriter := any(corpus).(api.Writer)
	assert.False(t, isWriter, "a read handle must not be assertable to the write surface")

	type localWriter interface {
		PutDocument(ctx context.Context, doc api.Document, expectedVersion int64) (int64, error)
	}
	_, isLocal := any(corpus).(localWriter)
	assert.False(t, isLocal, "nor to a locally declared interface of the same shape")
}
