package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/rules/api"
)

// Store owns the policies table.
type Store struct {
	db *sqlx.DB
}

// NewStore returns a Store over an existing sqlx.DB handle.
func NewStore(db *sqlx.DB) *Store {
	if db == nil {
		panic("rules policy.NewStore: db must not be nil")
	}
	return &Store{db: db}
}

// Get returns the policy row named `name`. Returns api.ErrPolicyNotFound
// if no row exists -- callers that bootstrap from the seed should use
// api.DefaultPolicyName and can treat ErrPolicyNotFound as an
// operational anomaly (the bootstrap schema seeds it).
func (s *Store) Get(ctx context.Context, name string) (api.BlocklistPolicy, error) {
	var row struct {
		Name      string    `db:"name"`
		Version   int64     `db:"version"`
		Blocklist []byte    `db:"blocklist"`
		UpdatedAt time.Time `db:"updated_at"`
		UpdatedBy string    `db:"updated_by"`
	}
	err := s.db.GetContext(ctx, &row, `
		SELECT name, version, blocklist, updated_at, updated_by
		FROM policies
		WHERE name = ?
	`, name)
	if errors.Is(err, sql.ErrNoRows) {
		return api.BlocklistPolicy{}, api.ErrPolicyNotFound
	}
	if err != nil {
		return api.BlocklistPolicy{}, fmt.Errorf("query policy %q: %w", name, err)
	}

	var bl api.Blocklist
	if err := json.Unmarshal(row.Blocklist, &bl); err != nil {
		return api.BlocklistPolicy{}, fmt.Errorf("decode blocklist for policy %q: %w", name, err)
	}
	return api.BlocklistPolicy{
		Name:      row.Name,
		Version:   row.Version,
		Blocklist: bl,
		UpdatedAt: row.UpdatedAt,
		UpdatedBy: row.UpdatedBy,
	}, nil
}

// Update atomically bumps the named policy's version and replaces its
// blocklist. Paths + Hashes are normalised (sorted + deduplicated,
// paths trimmed) and validated before persisting so the wire payload
// the extension sees is canonical and well-formed regardless of
// input order.
//
// Returns the new BlocklistPolicy with the bumped version. If the row
// is missing Update inserts it at version 1; callers don't need to
// distinguish insert vs update. Actor must be non-empty.
//
// Validation: paths must be absolute filesystem paths (start with
// '/'); hashes must be 64-character lowercase hex (SHA-256). An
// invalid entry fails the whole update so a bad policy never gets
// versioned, audited, and fanned out.
func (s *Store) Update(ctx context.Context, req api.UpdateRequest) (api.BlocklistPolicy, error) {
	if req.Name == "" {
		return api.BlocklistPolicy{}, fmt.Errorf("%w: name is required", api.ErrInvalidUpdateRequest)
	}
	if strings.TrimSpace(req.Actor) == "" {
		return api.BlocklistPolicy{}, fmt.Errorf("%w: actor is required", api.ErrInvalidUpdateRequest)
	}
	normalized := normalizeBlocklist(req.Paths, req.Hashes)
	if err := validateBlocklist(normalized); err != nil {
		return api.BlocklistPolicy{}, err
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return api.BlocklistPolicy{}, fmt.Errorf("marshal blocklist: %w", err)
	}

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return api.BlocklistPolicy{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // Rollback after commit is a no-op.

	// Upsert so the row is created if the seed migration hasn't yet
	// landed on a fresh DB. VALUES()-style assignment bumps the version
	// by one on every PUT; the initial insert starts at 1.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO policies (name, version, blocklist, updated_at, updated_by)
		VALUES (?, 1, ?, NOW(6), ?)
		ON DUPLICATE KEY UPDATE
			version    = version + 1,
			blocklist  = VALUES(blocklist),
			updated_at = NOW(6),
			updated_by = VALUES(updated_by)
	`, req.Name, payload, req.Actor); err != nil {
		return api.BlocklistPolicy{}, fmt.Errorf("upsert policy %q: %w", req.Name, err)
	}

	// Read the row we just wrote INSIDE the same tx, before commit.
	// Reading via Get after Commit leaves a window where another admin
	// update can interleave and we'd return (and fan out) someone
	// else's version; REPEATABLE READ inside a tx prevents that.
	var row struct {
		Name      string    `db:"name"`
		Version   int64     `db:"version"`
		Blocklist []byte    `db:"blocklist"`
		UpdatedAt time.Time `db:"updated_at"`
		UpdatedBy string    `db:"updated_by"`
	}
	if err := tx.GetContext(ctx, &row, `
		SELECT name, version, blocklist, updated_at, updated_by
		FROM policies
		WHERE name = ?
	`, req.Name); err != nil {
		return api.BlocklistPolicy{}, fmt.Errorf("read updated policy %q: %w", req.Name, err)
	}
	if err := tx.Commit(); err != nil {
		return api.BlocklistPolicy{}, fmt.Errorf("commit policy update: %w", err)
	}

	var bl api.Blocklist
	if err := json.Unmarshal(row.Blocklist, &bl); err != nil {
		return api.BlocklistPolicy{}, fmt.Errorf("decode updated blocklist for policy %q: %w", req.Name, err)
	}
	return api.BlocklistPolicy{
		Name:      row.Name,
		Version:   row.Version,
		Blocklist: bl,
		UpdatedAt: row.UpdatedAt,
		UpdatedBy: row.UpdatedBy,
	}, nil
}

// hashPattern is a 64-character lowercase hex string, the canonical
// SHA-256 representation. Lowercase enforced at the validation
// boundary because the normalization step upstream lowercases input.
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// validateBlocklist enforces the documented contract: paths must be
// absolute (start with "/"), hashes must be 64-char lowercase hex.
// Returns ErrInvalidPath / ErrInvalidHash with a wrapped descriptive
// message naming the first offending entry so operators can fix the
// PUT and retry.
func validateBlocklist(bl api.Blocklist) error {
	for _, p := range bl.Paths {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("%w: path %q must be absolute (start with '/')", api.ErrInvalidPath, p)
		}
	}
	for _, h := range bl.Hashes {
		if !hashPattern.MatchString(h) {
			return fmt.Errorf("%w: hash %q must be 64 lowercase hex chars (SHA-256)", api.ErrInvalidHash, h)
		}
	}
	return nil
}

// normalizeBlocklist returns a deterministic blocklist: paths trimmed
// + deduped + sorted (with macOS canonicalization), hashes lowercased
// + deduped + sorted. Nil slices become empty so the JSON output is
// always an array, never null.
func normalizeBlocklist(paths, hashes []string) api.Blocklist {
	bl := api.Blocklist{
		Paths:  dedupSort(paths, func(s string) string { return canonicalizeMacOSPath(strings.TrimSpace(s)) }),
		Hashes: dedupSort(hashes, func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }),
	}
	if bl.Paths == nil {
		bl.Paths = []string{}
	}
	if bl.Hashes == nil {
		bl.Hashes = []string{}
	}
	return bl
}

func dedupSort(in []string, norm func(string) string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = norm(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// canonicalizeMacOSPath rewrites the legacy /tmp, /var, and /etc
// symlink prefixes to their /private/... canonical forms. ESF reports
// the post-resolve path on AUTH_EXEC, so a blocklist entry of
// /tmp/payload silently fails to deny when the executable resolves to
// /private/tmp/payload. Operators consistently type /tmp/foo and
// /etc/foo and expect those to work; we rewrite at the API boundary
// so the wire form matches what the kernel will compare against.
// Trailing /tmpfoo or /varlog (no slash before the rest) are NOT
// prefixes -- they pass through unchanged.
func canonicalizeMacOSPath(p string) string {
	switch {
	case strings.HasPrefix(p, "/tmp/"):
		return "/private/tmp/" + p[len("/tmp/"):]
	case p == "/tmp":
		return "/private/tmp"
	case strings.HasPrefix(p, "/var/"):
		return "/private/var/" + p[len("/var/"):]
	case p == "/var":
		return "/private/var"
	case strings.HasPrefix(p, "/etc/"):
		return "/private/etc/" + p[len("/etc/"):]
	case p == "/etc":
		return "/private/etc"
	}
	return p
}
