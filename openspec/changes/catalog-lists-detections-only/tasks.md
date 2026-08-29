# Tasks

- [x] Add the opt-in `NonDetection` interface and the `projection` / `health` kinds to `server/rules/api`.
- [x] Declare `application_control_block` a projection, next to the reasoning in its own file.
- [x] Declare `sensor_recovery_failed` a health signal, likewise.
- [x] Filter non-detections out of `service.Service.List`, leaving `ActiveRules` untouched.
- [x] Route `bootstrap.CatalogOnly` through the service so the filter has exactly one implementation.
- [x] Pin the classification in a catalog test that fails in both directions.
- [x] Scope the "every rule maps to a technique" assertion to detections.
- [x] Retire the by-name invariant exemption in favour of the classification.
- [x] Regenerate `docs/detection-rules.md` and `docs/attack-navigator-layer.json`.
- [x] Verify the ATT&CK layer keeps every technique it had.
