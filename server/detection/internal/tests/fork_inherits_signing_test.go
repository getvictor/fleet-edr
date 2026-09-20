//go:build integration

// The code-signing identity a fork-without-exec child inherits from its parent (issue #1123). The fork already inherited the
// parent's PATH, correctly, because a forked child runs its parent's binary until it execs. It left code_signing, sha256 and cdhash
// NULL, so the row named a binary with no signature for it and every signature exclusion missed the process while matching an
// exec'd instance of the same tool.
//
// Measured on edr-dev: of that host's sshd-session rows, 883 carried a signature and 896 carried none, split exactly by whether an
// exec event had been seen. sshd forks a child per connection and that child serves the session without exec'ing.
//
// Both implementations of the lookup are asserted, as in parentimage_generation_test.go: the store's SQL is the per-event
// reference, the batch overlay is what production folds against, and the differential test cannot separate them because both of its
// arms drive the overlay.

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/graph"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
)

// The two signed images these scenarios distinguish. Real shapes: a Developer ID binary carries a team, an Apple binary carries the
// platform flag and no team, and an exclusion is written against whichever the parent had.
const (
	vendorSigning   = `{"team_id":"Q6L2SF6YDW","signing_id":"com.vendor.tool","flags":1}`
	platformSigning = `{"signing_id":"com.apple.sshd","is_platform_binary":true}`
	vendorSHA       = "aaaa1111"
	vendorCDHash    = "cdcd2222"
	platformSHA     = "bbbb3333"
	platformCDHash  = "cdcd4444"
)

// execEvtSigned is execEvtVer's envelope plus the signing fields a real ESF exec carries. Kept here rather than widened into the
// shared builder because every other scenario in this package deliberately uses the unsigned shape.
func execEvtSigned(ts int64, pid, ppid int, path, codeSigning, sha, cdhash string) api.Event {
	return api.Event{
		EventID: "e" + strconv.FormatInt(ts, 10), HostID: "x", TimestampNs: ts, IngestedAtNs: ts + 1, EventType: "exec",
		Payload: json.RawMessage(fmt.Sprintf(
			`{"pid":%d,"ppid":%d,"path":%q,"uid":501,"gid":20,"code_signing":%s,"sha256":%q,"cdhash":%q}`,
			pid, ppid, path, codeSigning, sha, cdhash)),
	}
}

// persistedImage reads back what the builder actually stored for the newest row of (hostID, pid), as the image a child would
// inherit from it. The read reuses ParentImage so the projection is the lookup's own.
func persistedImage(ctx context.Context, t *testing.T, db *sqlx.DB, hostID string, pid int) mysql.ParentImage {
	t.Helper()
	var img mysql.ParentImage
	require.NoError(t, db.GetContext(ctx, &img,
		`SELECT path, code_signing, sha256, cdhash FROM processes WHERE host_id = ? AND pid = ? ORDER BY id DESC LIMIT 1`,
		hostID, pid))
	return img
}

// requireSameIdentity asserts two images carry the same signing identity, comparing the code_signing JSON as text because that is
// how it is stored and how the exclusion matcher reads it.
func requireSameIdentity(t *testing.T, want, got mysql.ParentImage, msg string) {
	t.Helper()
	if len(want.CodeSigning) == 0 {
		// JSONEq cannot compare two absent identities, and "neither carries one" is an answer these tests assert.
		assert.Empty(t, got.CodeSigning, msg)
	} else {
		assert.JSONEq(t, string(want.CodeSigning), string(got.CodeSigning), msg)
	}
	assert.Equal(t, want.SHA256, got.SHA256, msg)
	assert.Equal(t, want.CDHash, got.CDHash, msg)
}

// The defect itself. A daemon that forks a worker per connection is the shape that produced it, and the worker is what a detection
// chain names as its non-shell parent.
//
// spec:server-process-graph-builder/a-forked-process-inherits-its-parent-s-signature/a-forked-worker-carries-the-daemon-s-signature
func TestForkInheritsTheParentsSigningIdentity(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	store, db := openProcessStore(t)
	b := graph.NewBuilder(store, discardLogger())

	const host = "fork-inherits-signing"
	const parentPID, childPID = 700, 701
	const parentPath = "/usr/libexec/sshd"

	require.NoError(t, b.ProcessBatch(ctx, rewriteHost([]api.Event{
		forkEvt(100, parentPID, 1),
		execEvtSigned(101, parentPID, 1, parentPath, platformSigning, platformSHA, platformCDHash),
	}, host)))

	// The store's SQL answers with the identity, not just the path.
	resolved, err := store.GetParentImage(ctx, host, parentPID, 150)
	require.NoError(t, err)
	assert.Equal(t, parentPath, resolved.Path)
	requireSameIdentity(t, persistedImage(ctx, t, db, host, parentPID), resolved,
		"the lookup must answer with the parent's own identity")

	// And the overlay stores it on the child, which is what the exclusion matcher will read.
	require.NoError(t, b.ProcessBatch(ctx, rewriteHost([]api.Event{childForkEvt("child-fork", 150, childPID, parentPID)}, host)))

	child := persistedImage(ctx, t, db, host, childPID)
	assert.Equal(t, parentPath, child.Path, "the path inheritance this is extending")
	requireSameIdentity(t, resolved, child, "a forked child runs its parent's binary, so it carries that binary's signature")
}

// Inheritance copies what the parent has, including nothing. This is the fail-safe half: a chain whose parent's signature was never
// observed must still not be suppressed by a signature exclusion, and that depends on the child carrying no invented identity.
//
// spec:server-process-graph-builder/a-forked-process-inherits-its-parent-s-signature/a-fork-from-an-unsigned-parent-inherits-nothing
func TestForkFromAnUnsignedParentInheritsNoIdentity(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	store, db := openProcessStore(t)
	b := graph.NewBuilder(store, discardLogger())

	const host = "fork-inherits-nothing"
	const parentPID, childPID = 710, 711

	require.NoError(t, b.ProcessBatch(ctx, rewriteHost([]api.Event{
		forkEvt(100, parentPID, 1),
		execEvt(101, parentPID, 1, "/tmp/unsigned"), // execEvt carries no signing fields, as an unsigned binary's exec does
		childForkEvt("child-fork", 150, childPID, parentPID),
	}, host)))

	child := persistedImage(ctx, t, db, host, childPID)
	assert.Equal(t, "/tmp/unsigned", child.Path)
	assert.Empty(t, child.CodeSigning, "there was nothing to inherit, so nothing may be asserted")
	assert.Nil(t, child.SHA256)
	assert.Nil(t, child.CDHash)

	resolved, err := store.GetParentImage(ctx, host, parentPID, 150)
	require.NoError(t, err)
	assert.Empty(t, resolved.CodeSigning)
}

// An inherited identity must not outlive the image it describes. The exec that follows is what makes a forked child stop running
// its parent's binary, and the row has to say so.
//
// spec:server-process-graph-builder/a-forked-process-inherits-its-parent-s-signature/an-exec-replaces-an-inherited-identity
func TestAnExecReplacesTheInheritedIdentity(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	store, db := openProcessStore(t)
	b := graph.NewBuilder(store, discardLogger())

	const host = "exec-replaces-inherited"
	const parentPID, childPID = 720, 721

	require.NoError(t, b.ProcessBatch(ctx, rewriteHost([]api.Event{
		forkEvt(100, parentPID, 1),
		execEvtSigned(101, parentPID, 1, "/usr/libexec/sshd", platformSigning, platformSHA, platformCDHash),
		childForkEvt("child-fork", 150, childPID, parentPID),
	}, host)))

	inherited := persistedImage(ctx, t, db, host, childPID)
	require.JSONEq(t, platformSigning, string(inherited.CodeSigning), "the child starts out on its parent's image")

	require.NoError(t, b.ProcessBatch(ctx, rewriteHost([]api.Event{
		execEvtSigned(200, childPID, parentPID, "/opt/vendor/tool", vendorSigning, vendorSHA, vendorCDHash),
	}, host)))

	after := persistedImage(ctx, t, db, host, childPID)
	assert.Equal(t, "/opt/vendor/tool", after.Path)
	assert.JSONEq(t, vendorSigning, string(after.CodeSigning), "the exec'd image's identity, not the inherited one")
	assert.Equal(t, vendorSHA, *after.SHA256)
	assert.Equal(t, vendorCDHash, *after.CDHash)

	// And a grandchild forked after the exec inherits the new identity, which is what a chain parented by this process is matched on.
	require.NoError(t, b.ProcessBatch(ctx, rewriteHost([]api.Event{childForkEvt("grandchild-fork", 250, 722, childPID)}, host)))
	grandchild := persistedImage(ctx, t, db, host, 722)
	assert.JSONEq(t, vendorSigning, string(grandchild.CodeSigning))

	resolved, err := store.GetParentImage(ctx, host, childPID, 250)
	require.NoError(t, err)
	requireSameIdentity(t, after, resolved, "the store's lookup agrees with what the overlay stored")
}

// The identity has to come from the SAME image the path came from, and only when that image was actually in force. A re-exec chain
// is where those come apart: every row in it carries the generation's original fork timestamp and the rows differ only by exec time.
//
// spec:server-process-graph-builder/a-forked-process-inherits-its-parent-s-signature/a-forked-worker-carries-the-daemon-s-signature
// spec:server-process-graph-builder/a-forked-process-inherits-its-parent-s-signature/an-image-not-yet-in-force-lends-its-path-only
func TestTheInheritedIdentityComesFromTheImageInForce(t *testing.T) {
	t.Parallel()

	const parentPID = 730
	const firstPath, secondPath = "/usr/libexec/sshd", "/opt/vendor/tool"

	cases := []struct {
		desc      string
		forkAt    int64
		childPID  int
		wantPath  string
		wantSig   string // "" when the child must inherit no identity at all
		wantSHA   string
		whyItIsSo string
	}{
		{
			desc:      "forked between the two execs",
			forkAt:    300,
			childPID:  731,
			wantPath:  firstPath,
			wantSig:   platformSigning,
			wantSHA:   platformSHA,
			whyItIsSo: "the image in force at that instant, not whatever the pid ran last",
		},
		{
			desc:      "forked after the re-exec",
			forkAt:    500,
			childPID:  732,
			wantPath:  secondPath,
			wantSig:   vendorSigning,
			wantSHA:   vendorSHA,
			whyItIsSo: "the later image, both halves of it",
		},
		{
			// The documented last resort: the child's stamp falls inside its parent's own fork-to-exec window, so no image in the
			// chain had been applied yet and the EARLIEST one is the closest surviving evidence of the path. Its signature is not
			// evidence of anything, and inheriting it would let a signature exclusion suppress activity that never ran under it.
			desc:      "forked before any image in the chain had been applied",
			forkAt:    50,
			childPID:  733,
			wantPath:  firstPath,
			wantSig:   "",
			whyItIsSo: "the exec that produced this signature had not happened when the child forked",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			store, db := openProcessStore(t)
			b := graph.NewBuilder(store, discardLogger())
			host := "inherit-in-force-" + tc.desc

			// One generation, two images: the platform binary from 101, the vendor binary from 400. The parent forked at 40, so an
			// instant below 101 is inside its own fork-to-exec window.
			require.NoError(t, b.ProcessBatch(ctx, rewriteHost([]api.Event{
				forkEvt(40, parentPID, 1),
				execEvtSigned(101, parentPID, 1, firstPath, platformSigning, platformSHA, platformCDHash),
			}, host)))
			require.NoError(t, b.ProcessBatch(ctx, rewriteHost([]api.Event{
				execEvtSigned(400, parentPID, 1, secondPath, vendorSigning, vendorSHA, vendorCDHash),
			}, host)))

			require.NoError(t, b.ProcessBatch(ctx,
				rewriteHost([]api.Event{childForkEvt("child", tc.forkAt, tc.childPID, parentPID)}, host)))

			child := persistedImage(ctx, t, db, host, tc.childPID)
			assert.Equal(t, tc.wantPath, child.Path, "the path is inherited whatever the identity does")
			if tc.wantSig == "" {
				assert.Empty(t, child.CodeSigning, tc.whyItIsSo)
				assert.Nil(t, child.SHA256)
				assert.Nil(t, child.CDHash)
			} else {
				assert.JSONEq(t, tc.wantSig, string(child.CodeSigning), tc.whyItIsSo)
				assert.Equal(t, tc.wantSHA, *child.SHA256)
			}

			// The store's SQL and the batch overlay have to answer identically; only the overlay wrote the row above.
			resolved, err := store.GetParentImage(ctx, host, parentPID, tc.forkAt)
			require.NoError(t, err)
			assert.Equal(t, tc.wantPath, resolved.Path, "store predicate at fork time %d", tc.forkAt)
			requireSameIdentity(t, child, resolved, "the two implementations must agree")
		})
	}
}
