package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/migrations/runner"
	"github.com/fleetdm/edr/server/rulecontent/api"
	rulecontentmysql "github.com/fleetdm/edr/server/rulecontent/internal/mysql"
	rulecontentmigrations "github.com/fleetdm/edr/server/rulecontent/migrations"
)

// Deps is what the context needs to start.
type Deps struct {
	DB     *sqlx.DB
	Logger *slog.Logger
}

// RuleContent is the assembled context.
type RuleContent struct {
	store  *rulecontentmysql.Store
	logger *slog.Logger
}

// New builds the rulecontent context.
func New(deps Deps) (*RuleContent, error) {
	if deps.DB == nil {
		return nil, errors.New("rulecontent bootstrap: DB is required")
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &RuleContent{store: rulecontentmysql.New(deps.DB), logger: logger}, nil
}

// Corpus exposes the published read surface consumers hold.
func (r *RuleContent) Corpus() api.Corpus { return r.store }

// ApplySchema applies the rulecontent migrations. Idempotent (goose skips applied versions).
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	if db == nil {
		return errors.New("rulecontent ApplySchema: db must not be nil")
	}
	return runner.Up(ctx, db, rulecontentmigrations.FS, runner.Options{
		Context:   "rulecontent",
		TableName: "rulecontent_goose_db_version",
	})
}

// SeedFrom populates the corpus from fsys when the corpus is empty, and reports whether it wrote anything.
//
// Seeding rather than migrating the content in, because the content is not schema: it changes on its own cadence, it is large, and
// expressing the rule files as INSERT statements in a migration would make every future corpus change a schema change.
//
// include decides which of the walked files are content. Passing nil takes everything, which is what a caller with a directory of
// nothing but rules wants; the vendored corpus is not that, so cmd/main passes the loader's own definition.
//
// Guarded on EMPTY rather than on a version, and that is the important part. Once an operator can author rules (issue #767), a seed
// that ran on every boot would overwrite their work with the vendored corpus on the next restart. Empty is the only condition under
// which this can be certain it is not destroying something, so it is the only condition it acts on.
//
// The guard is enforced by the STORE, inside the transaction that writes, rather than checked here first. Checking here was the
// first version and it was wrong: emptiness read out here and acted on afterwards is a check-then-act, so a rule authored in that
// window would be deleted by the seed that had already decided there was nothing to lose. Narrow at startup, and losing an
// operator's content is not a consequence worth a narrow window.
func (r *RuleContent) SeedFrom(ctx context.Context, fsys fs.FS, root string, include func(path string) bool) (bool, error) {
	docs, err := readAll(fsys, root, include)
	if err != nil {
		return false, err
	}
	if len(docs) == 0 {
		// Nothing to seed is not an error: a deployment may legitimately ship no vendored corpus, and refusing to start would
		// make an empty corpus impossible to run with even deliberately.
		r.logger.WarnContext(ctx, "rulecontent: seed source holds no rule documents; corpus left empty", "root", root)
		return false, nil
	}

	api.SortDocuments(docs)
	// The store decides whether the corpus is empty, in the same transaction as the write. Reading the source first costs a walk
	// that is thrown away when another replica got there first, which is cheaper than the alternative: checking emptiness out
	// here would be a check-then-act, and content committed in that window would be deleted.
	seeded, version, err := r.store.ReplaceIfEmpty(ctx, docs)
	if err != nil {
		return false, err
	}
	if !seeded {
		return false, nil
	}
	r.logger.InfoContext(ctx, "rulecontent: corpus seeded", "documents", len(docs), "version", version, "root", root)
	return true, nil
}

// readAll walks fsys under root and collects every file as a Document, keeping the path the loader will read it under.
func readAll(fsys fs.FS, root string, include func(path string) bool) ([]api.Document, error) {
	var docs []api.Document
	err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		// The caller decides what counts as content, because the component that LOADS it owns that definition; a second copy of
		// the rule here would be a divergence nobody notices until a file is stored that the loader ignores, or vice versa.
		if include != nil && !include(path) {
			return nil
		}
		content, readErr := fs.ReadFile(fsys, path)
		if readErr != nil {
			return fmt.Errorf("read %q: %w", path, readErr)
		}
		docs = append(docs, api.Document{Path: path, Content: content})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk seed source %q: %w", root, err)
	}
	return docs, nil
}
