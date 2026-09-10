# Tasks

- [x] Compute, in the view that owns the shared focus, whether the chain resolved but produced no scopeable generations.
- [x] Render an explanation in the timeline for that case, distinct from the existing "scoped" label.
- [x] Unit-test the three states (scoped, degraded, unscoped-by-choice) at the timeline.
- [x] Unit-test the wiring, so deleting the computation fails a test rather than only the prop-level ones.
- [x] Mutation-check both: deleting the notice and forcing the computation false each fail a test.
