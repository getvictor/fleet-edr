//go:build darwin && cgo

package procpath

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPath_OfThisProcess(t *testing.T) {
	t.Parallel()
	want, err := os.Executable()
	require.NoError(t, err)
	want, err = filepath.EvalSymlinks(want)
	require.NoError(t, err)

	got, ok := Path(os.Getpid())
	require.True(t, ok)
	assert.Equal(t, want, got)
}

func TestPath_NoSuchProcess(t *testing.T) {
	t.Parallel()
	for _, pid := range []int{0, -1, 99_999_999} {
		_, ok := Path(pid)
		assert.Falsef(t, ok, "pid %d", pid)
	}
}
