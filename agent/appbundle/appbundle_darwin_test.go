//go:build darwin && cgo

package appbundle

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Against the host's own LaunchServices: every Mac has Terminal, and no app claims a made-up identifier.
func TestPaths(t *testing.T) {
	t.Parallel()
	assert.Contains(t, Paths("com.apple.Terminal"), "/System/Applications/Utilities/Terminal.app")
	assert.Empty(t, Paths("com.example.edr.no-such-app"))
	assert.Empty(t, Paths(""))
}
