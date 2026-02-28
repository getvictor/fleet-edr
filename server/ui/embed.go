// Package ui embeds the built React frontend assets for serving by the Go server.
package ui

import "embed"

//go:embed dist/*
var DistFS embed.FS
