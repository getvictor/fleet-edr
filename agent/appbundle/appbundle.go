// Package appbundle finds an installed application by its bundle identifier, for the agent's TCC enrichment (issue #1185): macOS
// names the app a TCC permission is about by bundle identifier, and the permission can only be judged by the code signature of the
// app that holds it, which is read from a path.
package appbundle
