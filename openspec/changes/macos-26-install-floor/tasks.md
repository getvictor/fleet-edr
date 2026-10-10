## 1. Build and installer

- [x] 1.1 `MACOSX_DEPLOYMENT_TARGET = 26.0` for the app and both extensions; all three targets compile with no availability errors
- [x] 1.2 `distribution.xml` allows `min="26.0"` and `volumeCheck()` refuses majors below 26
- [x] 1.3 `test/arch/macos_floor_test.go` holds the installer minimum and the deployment target equal

## 2. Docs

- [x] 2.1 ADR-0002 amendment, install and MDM docs, best-practices
