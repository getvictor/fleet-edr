# Go conventions

Go coding conventions for the EDR project, derived from the Fleet codebase.

## Database access (sqlx)

Use `github.com/jmoiron/sqlx` instead of raw `database/sql`. This gives us struct scanning, named
parameters, and `IN` clause expansion.

### Struct tags

Use `db:"column_name"` tags on all model structs that map to database rows:

```go
type Process struct {
    ID         int64   `db:"id" json:"id"`
    HostID     string  `db:"host_id" json:"host_id"`
    PID        int     `db:"pid" json:"pid"`
    PPID       int     `db:"ppid" json:"ppid"`
    Path       string  `db:"path" json:"path"`
    ForkTimeNs int64   `db:"fork_time_ns" json:"fork_time_ns"`
}
```

### Query methods

Prefer context-aware sqlx methods:

```go
// Single row
var proc Process
err := sqlx.GetContext(ctx, db, &proc, "SELECT * FROM processes WHERE id = ?", id)

// Multiple rows
var procs []Process
err := sqlx.SelectContext(ctx, db, &procs, "SELECT * FROM processes WHERE host_id = ?", hostID)

// IN clauses
query, args, err := sqlx.In("SELECT * FROM processes WHERE id IN (?)", ids)
err = sqlx.SelectContext(ctx, db, &procs, query, args...)
```

### Transactions

Use `sqlx.Tx` for transactional operations:

```go
tx, err := db.BeginTxx(ctx, nil)
if err != nil {
    return fmt.Errorf("begin tx: %w", err)
}
defer tx.Rollback()

// ... operations ...

return tx.Commit()
```

## Testing (testify)

Use `github.com/stretchr/testify` for assertions. Import `require` for must-pass checks and `assert`
for soft checks.

### require vs assert

- **`require`**: stops the test immediately on failure. Use for preconditions and setup steps
  where continuing would cause confusing follow-on failures.
- **`assert`**: records the failure but continues. Use for checking multiple independent properties
  of a result.

```go
import (
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestInsertProcess(t *testing.T) {
    store := openTestStore(t)

    err := store.InsertProcess(t.Context(), proc)
    require.NoError(t, err)

    got, err := store.GetProcessByPID(t.Context(), "host-1", 42)
    require.NoError(t, err)
    assert.Equal(t, "host-1", got.HostID)
    assert.Equal(t, 42, got.PID)
    assert.Equal(t, "/usr/bin/curl", got.Path)
}
```

### Table-driven tests

Use table-driven tests with `t.Run()` for related scenarios:

```go
func TestParseEvent(t *testing.T) {
    cases := []struct {
        name      string
        input     string
        wantType  string
        wantErr   bool
    }{
        {"exec event", `{"event_type":"exec"...}`, "exec", false},
        {"invalid json", `{bad`, "", true},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            got, err := parseEvent(tc.input)
            if tc.wantErr {
                require.Error(t, err)
                return
            }
            require.NoError(t, err)
            assert.Equal(t, tc.wantType, got.EventType)
        })
    }
}
```

### Context in tests

Use `t.Context()` instead of `context.Background()`.

## Error handling

Wrap errors with `fmt.Errorf` and `%w` to preserve the error chain. Include a short description of
the operation that failed:

```go
if err != nil {
    return fmt.Errorf("insert process: %w", err)
}
```

For database not-found cases, check `sql.ErrNoRows` and return nil:

```go
if errors.Is(err, sql.ErrNoRows) {
    return nil, nil
}
```

## Logging (slog)

Use Go's standard `log/slog` package for structured logging. Pass the logger as a dependency rather
than using a global.

```go
type Handler struct {
    store  *store.Store
    logger *slog.Logger
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    h.logger.Info("received request", "method", r.Method, "path", r.URL.Path)
}

func (h *Handler) handleError(w http.ResponseWriter, msg string, err error, code int) {
    h.logger.Error(msg, "err", err)
    http.Error(w, msg, code)
}
```

## HTTP handlers

Use Go 1.22+ `http.ServeMux` method routing (`GET /path/{param}`). Extract path params with
`r.PathValue()`. This is the recommended starting point for new Go projects. If we later need
middleware chaining or more complex routing, `go-chi/chi` is the idiomatic step up (the fleet project
uses `gorilla/mux` for historical reasons).

### Handler structure

Each package exposes a `RegisterRoutes(mux *http.ServeMux)` method:

```go
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
    mux.HandleFunc("GET /api/v1/hosts", h.listHosts)
    mux.HandleFunc("GET /api/v1/hosts/{host_id}/tree", h.getTree)
}
```

### JSON responses

Use `json.NewEncoder(w).Encode(v)` for responses and `json.NewDecoder(r.Body).Decode(&v)` for
requests.

## Import grouping

Group imports in two blocks separated by a blank line: standard library first, then third-party and
internal packages:

```go
import (
    "context"
    "database/sql"
    "fmt"
    "log/slog"

    "github.com/jmoiron/sqlx"
    "github.com/getvictor/fleet-edr/server/store"
)
```

## Naming conventions

- **Receiver variables**: short names — `s` for Store, `h` for Handler, `b` for Builder, `q` for Query.
- **Avoid numbers in names**: use descriptive names like `configReqWithBadSignature` not `configReq3`.
- **Use `any`** instead of `interface{}`.
- **Line wrap** at 150 characters including comments.

## Code style

- Use sentence case for headings and comments.
- Do not add comments or docstrings to code you did not change.
- Prefer simple, direct code over abstractions for one-off operations.
