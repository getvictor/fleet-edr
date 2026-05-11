// Sections C+D+F.4 live in sections-c-d-f.spec.ts so they share one
// rebuildQAState() call (the break-glass setup endpoint is globally
// rate-limited, so running setup once per section trips it on the
// third invocation). Kept as a stub so an operator searching for
// "role-matrix" still finds the right entry point.
//
// Run: npm run qa
