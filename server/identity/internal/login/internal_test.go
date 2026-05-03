package login

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLogin_RedactsPasswordInErrorLogs locks in the loginRequest
// String() guard. White-box test: stays in `package login` so it can
// touch the unexported loginRequest type. The DB-using handler tests
// live in handler_test.go (package login_test) to avoid the
// testdb -> identity/bootstrap -> identity/internal/login cycle.
func TestLogin_RedactsPasswordInErrorLogs(t *testing.T) {
	req := loginRequest{Email: "a@b.com", Password: "hunter2"}
	s := req.String()
	assert.NotContains(t, s, "hunter2")
	assert.Contains(t, s, "[redacted]")
}
