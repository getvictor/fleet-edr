# Tasks

- [x] Walk from the resolved connecting generation instead of re-resolving the PID at the raw timestamp
- [x] Make the ancestor hops exact-first then padded, reusing the existing helper
- [x] Pad the shell window's lower bound only
- [x] Rename the pad and correct the clock-drift rationale, here and in the copy in `graph/query.go`
- [x] Tests for the measured skew shape and for the bound still holding beyond the pad, each mutation-checked
- [x] Spec delta
