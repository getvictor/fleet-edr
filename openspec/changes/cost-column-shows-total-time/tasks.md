# Tasks

- [x] Add `TotalEvalNs` to `api.RuleEvalSummary` and `SUM(eval_ns_sum)` to the aggregate query
- [x] Order the store's result by total rather than by mean
- [x] Carry the field through the UI API client type
- [x] Lead the Cost cell with the total, keeping the mean as the secondary figure
- [x] Sort the Cost column by total
- [x] Update the column note to name both figures
- [x] Integration coverage that the total is exact across days rather than a rounded product
- [x] UI coverage that the cell shows both figures and that the sort orders by total
- [x] Mutation-test the sort key and the total's exactness
