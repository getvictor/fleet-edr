# Tasks

## Clarify the web-ui detection-config scenarios

- [x] Rename "Disabling or monitoring a rule requires an operator reason" to "Disabling a rule requires an operator reason" and reword its WHEN/AND steps in the `web-ui` delta.
- [x] Rewrite the "Monitor is not an operator-selectable mode" scenario so the WHEN is opening the mode control and the two rule cases split across THEN/AND.
- [x] Retarget the spectrace marker at `ui/src/components/DetectionConfig/DetectionConfig.test.tsx` to the renamed scenario ID `disabling-a-rule-requires-an-operator-reason`.
- [x] `openspec validate --all --strict` and `go run ./tools/spectrace check --strict` green after archiving.
