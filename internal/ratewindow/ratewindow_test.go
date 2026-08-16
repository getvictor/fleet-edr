package ratewindow

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCounterAllow(t *testing.T) {
	t.Run("under the limit", func(t *testing.T) {
		c := New(time.Minute, 2)
		assert.True(t, c.Allow("host-a"))
		assert.True(t, c.Allow("host-a"))
	})

	t.Run("over the limit", func(t *testing.T) {
		c := New(time.Minute, 2)
		c.Allow("host-a")
		c.Allow("host-a")
		assert.False(t, c.Allow("host-a"))
	})

	t.Run("hosts are counted independently", func(t *testing.T) {
		c := New(time.Minute, 1)
		assert.True(t, c.Allow("host-a"))
		assert.True(t, c.Allow("host-b"))
	})

	t.Run("reset clears the window", func(t *testing.T) {
		c := New(time.Minute, 1)
		c.Allow("host-a")
		c.Reset()
		assert.True(t, c.Allow("host-a"))
	})
}
