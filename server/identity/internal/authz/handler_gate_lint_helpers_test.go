package authz_test

import (
	"os"
	"testing"
)

// mustGetwd is the small wrapper the lint test uses to fail loudly if
// os.Getwd surfaces an error. Kept as a tiny helper so the main lint
// file stays focused on the AST walk.
func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	return wd
}
