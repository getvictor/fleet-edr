package containment

import "time"

// SetNow replaces the converger's clock, so a test can place a sweep relative to a command's failure.
func (c *Converger) SetNow(now func() time.Time) { c.now = now }
