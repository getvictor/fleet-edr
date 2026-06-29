package identities_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	_ "github.com/go-sql-driver/mysql" // registers the "mysql" driver so sqlx.Open builds a (lazy, never-connected) handle.
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/internal/identities"
)

// fakeExec is a stub identities.Executor that returns a preset result/error, so the InsertWith / UpsertWith error-wrapping branches
// can be exercised without a database. Pinning these paths keeps #522's UpsertWith addition honest: a DB fault must surface as a
// wrapped error, never a bare driver error.
type fakeExec struct {
	res sql.Result
	err error
}

func (f fakeExec) ExecContext(context.Context, string, ...any) (sql.Result, error) {
	return f.res, f.err
}

// fakeResult satisfies sql.Result with a configurable LastInsertId error, so the post-exec LastInsertId() failure branch is reachable.
type fakeResult struct {
	id    int64
	idErr error
}

func (r fakeResult) LastInsertId() (int64, error) { return r.id, r.idErr }
func (r fakeResult) RowsAffected() (int64, error) { return 0, nil }

func TestInsertAndUpsertWith_WrapErrors(t *testing.T) {
	t.Parallel()
	// New requires a non-nil handle, but InsertWith / UpsertWith run on the passed Executor, not s.db. A lazy sqlx.Open handle (no
	// connection is made until a query runs, and none does) satisfies the guard without needing a real database.
	db, err := sqlx.Open("mysql", "root@tcp(127.0.0.1:0)/identities_unit_test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	s := identities.New(db)
	ctx := context.Background()
	execErr := errors.New("boom")
	lastIDErr := errors.New("no last id")

	t.Run("InsertWith wraps exec error", func(t *testing.T) {
		t.Parallel()
		_, err := s.InsertWith(ctx, fakeExec{err: execErr}, 1, "local_password", "a@b.test")
		require.Error(t, err)
		require.ErrorIs(t, err, execErr)
		assert.Contains(t, err.Error(), "identities: insert")
	})

	t.Run("InsertWith wraps LastInsertId error", func(t *testing.T) {
		t.Parallel()
		_, err := s.InsertWith(ctx, fakeExec{res: fakeResult{idErr: lastIDErr}}, 1, "local_password", "a@b.test")
		require.Error(t, err)
		require.ErrorIs(t, err, lastIDErr)
		assert.Contains(t, err.Error(), "last insert id")
	})

	t.Run("UpsertWith wraps exec error", func(t *testing.T) {
		t.Parallel()
		_, err := s.UpsertWith(ctx, fakeExec{err: execErr}, 1, "local_password", "a@b.test")
		require.Error(t, err)
		require.ErrorIs(t, err, execErr)
		assert.Contains(t, err.Error(), "identities: upsert")
	})

	t.Run("UpsertWith wraps LastInsertId error", func(t *testing.T) {
		t.Parallel()
		_, err := s.UpsertWith(ctx, fakeExec{res: fakeResult{idErr: lastIDErr}}, 1, "local_password", "a@b.test")
		require.Error(t, err)
		require.ErrorIs(t, err, lastIDErr)
		assert.Contains(t, err.Error(), "upsert last insert id")
	})

	t.Run("UpsertWith returns the row id on success", func(t *testing.T) {
		t.Parallel()
		id, err := s.UpsertWith(ctx, fakeExec{res: fakeResult{id: 42}}, 1, "local_password", "a@b.test")
		require.NoError(t, err)
		assert.Equal(t, int64(42), id)
	})
}
