## 1. Handlers

- [x] 1.1 `appcontrol_handler.go` `readAppControlBody`: read `limit+1`; if `len(body) > limit` return `413` via `writeAppControlErr(..., errCodeBodyTooLarge, errMsgBodyTooLarge)` before unmarshalling. Add the `errCodeBodyTooLarge = "application_control.body_too_large"` / `errMsgBodyTooLarge` constants.
- [x] 1.2 `detectionconfig_handler.go` `(*DetectionConfigHandler).decode`: read `detectionConfigReadBodyLimit+1`; if over the cap return `413` via `writeDetectionConfigErr(..., errCodeDCBodyTooLarge, ...)`. Add the `errCodeDCBodyTooLarge = "detection_config.body_too_large"` constant.

## 2. Tests

- [x] 2.1 `appcontrol_handler_test.go`: `TestReadAppControlBody_SizeLimit` (both per-route caps: at-limit clean, over-limit 413 + `application_control.body_too_large`). Carries the `spec:` marker for the app-control scenario.
- [x] 2.2 `detectionconfig_handler_test.go`: `TestDetectionConfigHandler_BodyTooLarge` (over-limit 413 + `detection_config.body_too_large`; normal 200/201). Carries the `spec:` marker for the detection-config scenario.

## 3. Verify

- [x] 3.1 `tmp/golangci-lint-custom run ./server/rules/internal/operator/...` (0 issues), `go build ./server/rules/...`, `go test -tags integration ./server/rules/internal/operator/... ./server/rules/internal/tests/`.
- [x] 3.2 `openspec validate --all --strict` + `spectrace --strict`.
