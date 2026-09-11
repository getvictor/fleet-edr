# Tasks

- [x] Bound `CountProcessTree` through the row query's access path
- [x] Carry `total_matched_capped` on the API type and the wire response
- [x] Set it in `BuildTree` and keep `truncated` meaning what it means today
- [x] Surface the floor in the UI so a capped total does not read as exact
- [x] Integration coverage: exact below the bound, exact AT the bound, floor past it, and the flag never set on an untruncated read
- [x] Mutation-test the bound and the flag
- [x] Re-measure on the dogfood host that the failing window now answers
- [x] Give the count a time budget so a sparse window that walks the whole range still answers
- [x] Prove `truncated` from a lookahead row, so it holds when the count cannot finish
- [x] Count one row past the bound so "more than N" is true rather than "at least N"
- [x] Spec the floor semantics on the UI side too, not only on the API
- [x] Pin the new wire field in the round-trip PBT and the field-name test
