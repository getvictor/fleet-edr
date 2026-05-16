// The real tests live in tools/comment-wrap-check/lint/analyzer_test.go; the standalone CLI is a one-liner over the
// singlechecker.Main entry point and has no logic worth a separate test surface. Kept as an empty in-package file rather than
// deleted so any tooling that recurses through .go files in the directory does not stumble on a missing-package quirk.
package main
