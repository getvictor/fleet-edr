// Section F.4 lives in sections-c-d-f.spec.ts. Section G (SQL-driven
// recovery) is already exercised by tests/auth/break-glass-setup.spec.ts
// + break-glass-login.spec.ts since the fixtures/db.ts mintBootstrapToken
// helper IS the SQL recovery path documented in docs/breakglass.md.
//
// Run: npm run qa
//   or: npx playwright test tests/qa/sections-c-d-f
