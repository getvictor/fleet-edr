// Package seed bootstraps the first-boot state that is too opinionated for DDL: the
// single admin user that the UI logs in as. Called from main.go right after the store
// is open but before the HTTP server starts accepting traffic.
//
// Design note: the seeded password is printed to stderr exactly once. If an operator
// misses the print (container stdout rotated, terminal cleared, etc.) the recovery
// path is to `DELETE FROM users WHERE email='admin@fleet-edr.local'` and restart —
// the seeder sees the empty table and generates a new password. That's not elegant,
// but a password-reset flow is explicitly out of scope for Phase 3.
package seed

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"

	"github.com/fleetdm/edr/server/users"
)

// DefaultAdminEmail is the well-known first-admin email. Operators can create further
// accounts post-v1.1; for MVP this is the only one.
const DefaultAdminEmail = "admin@fleet-edr.local"

// PasswordBytes is the size (in random bytes, pre-base64) of the generated admin
// password. 24 bytes → 32 base64url characters → ~192 bits of entropy, plenty against
// offline argon2 attacks.
const PasswordBytes = 24

// Admin seeds the initial admin user if the users table is empty. Returns the admin
// user (if any seeding happened) and the plaintext password that should be shown to
// the operator. If a user already exists it returns (nil, "", nil) so the caller can
// log at debug.
func Admin(ctx context.Context, us *users.Store, logger *slog.Logger, stderr io.Writer) (*users.User, string, error) {
	if us == nil {
		return nil, "", fmt.Errorf("seed.Admin: users store required")
	}
	if logger == nil {
		logger = slog.Default()
	}

	n, err := us.Count(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("count users: %w", err)
	}
	if n > 0 {
		logger.DebugContext(ctx, "admin seed skipped — users table non-empty")
		return nil, "", nil
	}

	pw, err := randomPassword()
	if err != nil {
		return nil, "", fmt.Errorf("generate admin password: %w", err)
	}
	u, err := us.Create(ctx, users.CreateRequest{Email: DefaultAdminEmail, Password: pw})
	if err != nil {
		return nil, "", fmt.Errorf("create admin user: %w", err)
	}

	// stderr banner so a human watching the log sees it during `docker run`. Not logged
	// through slog because even slog's text handler can quote / escape the string in
	// ways that make copy-paste tricky; raw writes win.
	if stderr != nil {
		fmt.Fprintln(stderr, "================================================================")
		fmt.Fprintln(stderr, "SEEDED ADMIN USER (captured once — save the password now)")
		fmt.Fprintf(stderr, "  Email:    %s\n", u.Email)
		fmt.Fprintf(stderr, "  Password: %s\n", pw)
		fmt.Fprintln(stderr, "================================================================")
	}

	// Structured log WITHOUT the password so SigNoz has the event without leaking the
	// credential. Audit reviewers can correlate this line to a `login ok` line later.
	logger.InfoContext(ctx, "admin user seeded",
		"edr.user.id", u.ID,
		"edr.user.email", u.Email,
	)
	return u, pw, nil
}

// randomPassword returns a base64url-encoded 24-byte random password. Base64url rather
// than base62 because the stdlib gives it to us for free and the trailing `=` padding
// is irrelevant for us (rawURLEncoding omits it).
func randomPassword() (string, error) {
	buf := make([]byte, PasswordBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
