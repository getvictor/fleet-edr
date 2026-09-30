//go:build darwin && cgo

package appbundle

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Against the host's own LaunchServices: every Mac has Terminal, and no app claims a made-up identifier.
func TestPath(t *testing.T) {
	t.Parallel()
	path, ok := Path("com.apple.Terminal")
	assert.True(t, ok)
	assert.Equal(t, "/System/Applications/Utilities/Terminal.app", path)

	_, ok = Path("com.example.edr.no-such-app")
	assert.False(t, ok)
	_, ok = Path("")
	assert.False(t, ok)
}
