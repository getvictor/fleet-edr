---
name: find-prior-art
description: Search the codebase for an existing helper, type, validator, constant, SQL query, or HTTP route before writing a new one, so AI-generated code extends what already exists instead of cloning it. Use BEFORE generating any non-trivial new code, and when the user asks to "check for prior art", "is there an existing X", or "avoid duplication".
metadata:
  author: fleet-edr
  version: "1.0"
---

# Find prior art

Before writing a new helper, type, validator, constant, SQL query, or HTTP route, search for one that already exists and extend it instead of adding a parallel implementation. Semantic duplication (the same logic under a different name) is the dominant defect in AI-generated code, and it is invisible to the SonarCloud duplication gate, which matches only lexical tokens.

## When to run

Run this before generating any non-trivial new code: a function or method beyond a one-line wrapper, a struct or interface, a named constant or sentinel error, a SQL statement, or an HTTP handler. Skip it for test bodies and for edits confined to an existing function.

## Where to look

The server is five bounded contexts under `server/`: `identity`, `endpoint`, `rules`, `response`, `detection` (ADR-0004). Cross-context code lives in the imported `api/` package; code shared by server and agent lives in `internal/`. The agent is under `agent/`, the extension under `extension/edr/`.

Search in this order:

1. The owning bounded context (or `agent/` package) for a local equivalent.
2. `internal/` and `api/` for a shared equivalent the new code should call instead.
3. The whole tree, to catch a third copy that should become the shared one.

## How to search

Search the concept, not the exact name you were about to type. Look for the verb and the domain noun separately, because the existing helper was probably named differently.

```bash
# Functions by concept: adjust the verb stem and domain noun to your case
rg -n --type go -i 'func .*(normaliz|sanitiz|validat).*host' server internal api

# Existing type or interface for the shape you need
rg -n --type go 'type .*(HostID|Enrollment|Session)' server internal

# Existing HTTP route before registering a new one
rg -n --type go '(Handle|HandleFunc|\.(Get|Post|Put|Delete))\(' server | rg -i 'enroll'

# Existing SQL for the same table and operation
rg -n --type go -i 'INSERT INTO audit_events|SELECT .* FROM sessions' server
```

## What to report

Return exactly one verdict:

- Reuse: name the existing symbol (`pkg.Func` at `path:line`) and state how the new requirement should call or extend it.
- Promote to shared: an equivalent exists in a sibling context; it should move to `internal/` or `api/` and both call sites use the one copy. Never copy logic sideways between contexts.
- None found: state that the search ran, list the terms tried, and name the package the new code should live in (the owning context, or `internal/` if more than one context needs it).

Do not report "none found" without showing the search terms. A shallow search that misses the existing helper is the exact failure mode this skill exists to prevent.
