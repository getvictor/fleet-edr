package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"slices"
	"strings"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/migrations/runner"
	"github.com/fleetdm/edr/server/rulecontent/api"
	"github.com/fleetdm/edr/server/rulecontent/internal/authoring"
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
func (r *RuleContent) Corpus() api.Corpus { return readOnlyCorpus{inner: r.store} }

// readOnlyCorpus narrows the store to the read surface, and the wrapper is the point rather than ceremony.
//
// Returning the store directly typed as api.Corpus does NOT make the write methods unreachable: the dynamic type still carries
// PutDocument and DeleteDocument, so any consumer holding a Corpus can type-assert to api.Writer, or to a local interface with
// the same shape, and persist whatever it likes. Every guarantee the authoring path makes about validation would then hold only
// for callers that chose to go through it, which is not a guarantee at all.
//
// A struct with only the two read methods has nothing to assert to. The write surface reaches its caller by being handed over
// deliberately, not by being discoverable on something handed over for another purpose.
type readOnlyCorpus struct{ inner api.Corpus }

func (c readOnlyCorpus) Documents(ctx context.Context) ([]api.Document, error) {
	return c.inner.Documents(ctx)
}
func (c readOnlyCorpus) Version(ctx context.Context) (int64, error) { return c.inner.Version(ctx) }

// Author builds the authoring lifecycle over this context's storage, validated by v.
//
// The validator is INJECTED rather than constructed here, which is what keeps the ADR-0021 seam intact: the only honest validator
// is the corpus loader, the loader lives in `rules` because it produces evaluatable rules, and this context imports no other
// context's api. cmd/main supplies the implementation and this package never learns what it is.
//
// A nil validator is an error rather than a permissive default. The whole reason this surface exists is that rule content is
// untrusted input, so a construction that silently skips validation would be worse than no surface at all.
func (r *RuleContent) Author(v api.Validator) (api.Author, error) {
	return authoring.New(r.Corpus(), r.store, v)
}

// Replace installs a corpus wholesale, returning the version it now carries.
//
// Unlike SeedFrom this OVERWRITES whatever is stored, which is what publishing content means: the caller has decided what the
// corpus should be.
//
// The write and the version bump are one transaction, and the guarantee that buys is ONE-WAY: a reader can never observe the new
// version paired with the previous documents. It does not make a version read and a document read atomic with each other, so a
// reader that takes them separately can still pair an older version with newer documents. That direction is harmless and is what
// the consumer's version-before-documents ordering relies on, since the next poll sees the difference and converges.
//
// The caller's slice is cloned before sorting. Publishing should not reorder a value the caller still holds, least of all when the
// write then fails.
//
// This is the seam the import and authoring paths (issues #767, #768) write through. It exists here rather than on the store so
// that a caller outside this context can publish content without reaching into its internals.
func (r *RuleContent) Replace(ctx context.Context, docs []api.Document) (int64, error) {
	sorted := slices.Clone(docs)
	api.SortDocuments(sorted)
	version, err := r.store.Replace(ctx, sorted)
	if err != nil {
		return 0, err
	}
	r.logger.InfoContext(ctx, "rulecontent: corpus replaced", "documents", len(sorted), "version", version)
	return version, nil
}

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

// UpgradePackFrom installs the shipped rule content in this build over the shipped content the corpus holds, and reports whether
// anything changed.
//
// The counterpart to SeedFrom, which acts only on an EMPTY corpus. Once a deployment has seeded, the seed can never run again, so
// without this a corpus keeps its first generation of shipped rules forever: an operator upgrading the product to get new
// detections would not get them, and nothing would say so. That is a security regression rather than an inconvenience, which is
// why this runs on its own rather than waiting to be asked.
//
// It replaces only the SHIPPED half. An operator's own rules survive an upgrade, including one written over a shipped rule's path,
// and their tuning survives because per-rule mode, severity overrides and exclusions live in detection_rule_settings keyed by rule
// id rather than in these files. That separation is what makes upgrading safe, and it is the reason issue #768 states the two
// acceptance criteria it does.
//
// identity maps a document's path to the rule it loads as, and is supplied rather than derived here for the same reason the
// provenance projection is: the derivation belongs to the loader. It is what keeps a pack document from colliding with an
// operator's rule of the same identity at a different path, which would leave a corpus that does not load AT ALL.
//
// Failure is reported rather than fatal, matching SeedFrom for the same reason: a deployment that cannot install a newer pack
// still detects with the pack it has.
func (r *RuleContent) UpgradePackFrom(
	ctx context.Context, fsys fs.FS, root string, include func(path string) bool, identity api.RuleIdentity,
) (bool, error) {
	docs, err := readAll(fsys, root, include)
	if err != nil {
		return false, err
	}
	if len(docs) == 0 {
		// A build shipping no rules must not be read as "delete every shipped rule you have". Seeding treats this as a legitimate
		// empty corpus because there is nothing to lose; here there is, so the only safe reading is that something is wrong with
		// this build's embedded content rather than that the pack is deliberately empty.
		r.logger.WarnContext(ctx, "rulecontent: this build ships no rule documents; leaving the stored pack alone", "root", root)
		return false, nil
	}

	api.SortDocuments(docs)
	installed, err := r.store.UpgradeVendoredTo(ctx, docs, identity)
	if err != nil {
		return false, err
	}
	// Reported even when nothing else changed. A rule the pack ships and this deployment does not run is a divergence the
	// operator chose, by writing their own rule of the same identity, and it is still the only place they would learn of it.
	if len(installed.Skipped) > 0 {
		r.logger.InfoContext(ctx, "rulecontent: kept the operator's own rules over the ones this build ships",
			"documents", strings.Join(installed.Skipped, ","))
	}
	if !installed.Changed {
		return false, nil
	}
	r.logger.InfoContext(ctx, "rulecontent: installed the rule pack from this build",
		"documents", len(docs), "version", installed.Version)
	return true, nil
}

// Packs returns the pack lifecycle bound to the build's own pack, satisfying api.PackLifecycle.
//
// The binding is the point. Status and rollback both need to know what shipped content this build carries, and the caller in the
// rules context has no business reading it: that is what made the port's two methods take no arguments. Closing over the FS here
// is what lets them.
//
// identity maps a document's path to the rule it loads as, and comes from the caller for the reason it does everywhere else in
// this context: the derivation belongs to the loader (#873), and a copy of it here would agree until one of them changed.
func (r *RuleContent) Packs(fsys fs.FS, root string, include func(path string) bool, identity api.RuleIdentity) api.PackLifecycle {
	return boundPacks{rc: r, fsys: fsys, root: root, include: include, identity: identity}
}

// boundPacks is the pack lifecycle with the build's pack and the loader's identity function already supplied.
type boundPacks struct {
	rc       *RuleContent
	fsys     fs.FS
	root     string
	include  func(path string) bool
	identity api.RuleIdentity
}

func (b boundPacks) Status(ctx context.Context) (api.PackStatus, error) {
	return b.rc.PackStatusFrom(ctx, b.fsys, b.root, b.include, b.identity)
}

func (b boundPacks) Rollback(ctx context.Context) (api.PackRollback, error) {
	return b.rc.RollbackPackTo(ctx, b.identity)
}

// RollbackPackTo restores the shipped content the last upgrade replaced, and records that the pack this build carries was
// declined so a restart does not reinstall it.
//
// The pack being declined is read from what the UPGRADE recorded rather than from the build this process is running, which review
// caught: during a rolling deployment a rollback served by an older replica would otherwise decline that replica's pack and leave
// the newer one free to reinstall on the next start.
//
// identity is needed for the same reason the install path needs it: a rule the operator has taken over since the upgrade must not
// be taken back by the restore.
func (r *RuleContent) RollbackPackTo(ctx context.Context, identity api.RuleIdentity) (api.PackRollback, error) {
	rolled, err := r.store.RollbackPack(ctx, identity)
	if err != nil {
		return api.PackRollback{}, err
	}
	if len(rolled.Withheld) > 0 {
		r.logger.InfoContext(ctx, "rulecontent: kept the operator's own rules over the ones being restored",
			"documents", strings.Join(rolled.Withheld, ","))
	}
	r.logger.InfoContext(ctx, "rulecontent: rolled back to the previously installed rule pack",
		"pack", rolled.Restored, "version", rolled.Version)
	return rolled, nil
}

// PackStatusFrom reports what shipped content this deployment runs and how it differs from the pack in this build.
func (r *RuleContent) PackStatusFrom(
	ctx context.Context, fsys fs.FS, root string, include func(path string) bool, identity api.RuleIdentity,
) (api.PackStatus, error) {
	docs, err := readAll(fsys, root, include)
	if err != nil {
		return api.PackStatus{}, err
	}
	api.SortDocuments(docs)
	return r.store.PackStatusAgainst(ctx, docs, identity)
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
