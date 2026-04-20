# Architecture Decision Records

Architecture Decision Records (ADRs) capture the *why* behind non-obvious
architectural choices. The code shows *what* is true today; ADRs preserve the
context, constraints, and alternatives considered, so future maintainers (and
future-you) don't reverse-engineer incorrect assumptions.

## When to write one

Write an ADR when a decision is:

- Hard or expensive to reverse ("which database", "one binary vs split",
  "which auth flow").
- Non-obvious from reading the code ("why ESF and not a kext", "why MySQL and
  not Postgres").
- Going to be questioned again in six months by someone who wasn't in the
  original discussion.
- A deliberate *non-decision* (something common the project will not do, with
  rationale).

Do **not** write an ADR for a style nit, a local refactor, or a decision the
code unambiguously documents.

## Format

Every ADR is a Markdown file named `NNNN-short-slug.md` where `NNNN` is the
next available 4-digit number. Use the template at `template.md`.

Each ADR is immutable after it lands. When a decision changes, write a *new*
ADR that supersedes the old one (mark the old file `Status: Superseded by
NNNN` and link both directions). This gives you a trail of reasoning across
time, not a single mutable "current view".

## Index

| ID | Title | Status |
| -- | ----- | ------ |
| [0001](0001-single-go-module-with-internal.md) | Single Go module with `internal/` for shared code | Accepted |
| [0002](0002-macos-apple-silicon-mvp-only.md) | MVP ships macOS on Apple Silicon only | Accepted |
| [0003](0003-standalone-product-not-fleet-integrated.md) | EDR is a standalone product, Fleet is a deployment channel | Accepted |

## Tooling

No tooling. `cat docs/adr/*.md` is the viewer. The point of ADRs is that the
write-up itself is the product, not the automation around it.
