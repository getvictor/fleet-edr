package seed

// Phase 4b removed the random-password generation from this package
// (replaced by the bootstrap-token redemption flow in
// server/identity/internal/breakglass). The unit test that exercised
// that helper is gone with it; the package's behavior is covered by
// the integration tests in admin_test.go.
