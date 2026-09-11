# Tasks

- [x] Bound `CountProcessTree` through the row query's access path
- [x] Carry `total_matched_capped` on the API type and the wire response
- [x] Set it in `BuildTree` and keep `truncated` meaning what it means today
- [x] Surface the floor in the UI so a capped total does not read as exact
- [x] Integration coverage: exact below the bound, floor at the bound, flag set only at the bound
- [x] Mutation-test the bound and the flag
- [x] Re-measure on the dogfood host that the failing window now answers
