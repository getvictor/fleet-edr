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
	assert.JSONEq(t, string(want.CodeSigning), string(got.CodeSigning), msg)
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

// The identity has to come from the SAME image the path came from. A re-exec chain is where they can diverge: every row in it
// carries the generation's original fork timestamp and the rows differ only by exec time, so an identity selected by any other
// ordering would describe one binary's path with another binary's signature.
//
// spec:server-process-graph-builder/a-forked-process-inherits-its-parent-s-signature/a-forked-worker-carries-the-daemon-s-signature
func TestTheInheritedIdentityComesFromTheSameImageAsThePath(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	store, db := openProcessStore(t)
	b := graph.NewBuilder(store, discardLogger())

	const host = "inherit-same-image"
	const parentPID = 730
	const firstPath, secondPath = "/usr/libexec/sshd", "/opt/vendor/tool"

	// One generation, two images: the platform binary until 400, the vendor binary after it.
	require.NoError(t, b.ProcessBatch(ctx, rewriteHost([]api.Event{
		forkEvt(100, parentPID, 1),
		execEvtSigned(101, parentPID, 1, firstPath, platformSigning, platformSHA, platformCDHash),
	}, host)))
	require.NoError(t, b.ProcessBatch(ctx, rewriteHost([]api.Event{
		execEvtSigned(400, parentPID, 1, secondPath, vendorSigning, vendorSHA, vendorCDHash),
	}, host)))

	// A child forked between the two execs gets the image in force then: the first path AND the first signature.
	require.NoError(t, b.ProcessBatch(ctx, rewriteHost([]api.Event{childForkEvt("between", 300, 731, parentPID)}, host)))
	between := persistedImage(ctx, t, db, host, 731)
	assert.Equal(t, firstPath, between.Path)
	assert.JSONEq(t, platformSigning, string(between.CodeSigning),
		"the signature of the image in force, not of whatever the pid ran last")
	assert.Equal(t, platformSHA, *between.SHA256)

	// A child forked after the re-exec gets the second image, both halves.
	require.NoError(t, b.ProcessBatch(ctx, rewriteHost([]api.Event{childForkEvt("after", 500, 732, parentPID)}, host)))
	after := persistedImage(ctx, t, db, host, 732)
	assert.Equal(t, secondPath, after.Path)
	assert.JSONEq(t, vendorSigning, string(after.CodeSigning))
	assert.Equal(t, vendorSHA, *after.SHA256)

	// The store's SQL resolves both instants the same way the overlay did.
	early, err := store.GetParentImage(ctx, host, parentPID, 300)
	require.NoError(t, err)
	requireSameIdentity(t, between, early, "store predicate between the execs")
	late, err := store.GetParentImage(ctx, host, parentPID, 500)
	require.NoError(t, err)
	requireSameIdentity(t, after, late, "store predicate after the re-exec")
}
