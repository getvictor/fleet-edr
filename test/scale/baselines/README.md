# Scale-test baselines

`baseline.json` is the canonical M12 scale-test baseline captured on a representative developer machine. Treat it as a
hand-edited contract: regenerate by running

    task uat:scale -- --duration=30m --output=test/scale/baselines/baseline.json

against an idle dev:server, then `git diff` to confirm the change is intentional before committing.

Each baseline file is a `scale.Report` (see `test/scale/runner.go`); the `per_host` array is dropped from committed
baselines because it changes every run (random host UUIDs). Strip it manually before committing:

    jq 'del(.per_host)' test/scale/baselines/baseline.json > /tmp/b.json && mv /tmp/b.json test/scale/baselines/baseline.json

The plan's pass criteria (p99 < 250ms, zero errors) apply at the aggregate level; per-host latencies live in the JSON
report on disk during triage but not in the committed baseline.

Initial baseline: not yet captured. Run the command above to create `baseline.json`.
