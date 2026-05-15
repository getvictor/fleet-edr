package ui

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestFS_DefaultsToEmbedded(t *testing.T) {
	// An empty live-dir env must fall back to the compile-time embedded bundle.
	t.Setenv(LiveDirEnv, "")
	got, err := FS()
	if err != nil {
		t.Fatalf("FS() returned error: %v", err)
	}
	// The embedded bundle is built by `task build:ui` and always contains
	// index.html at the root. If this fails, the dist/ tree is stale or empty.
	if _, err := fs.Stat(got, "index.html"); err != nil {
		t.Fatalf("expected embedded FS to contain index.html, got %v", err)
	}
}

func TestFS_LiveDirOverrideReadsFromDisk(t *testing.T) {
	dir := t.TempDir()
	want := []byte("<!doctype html><html><body>live</body></html>")
	if err := os.WriteFile(filepath.Join(dir, "index.html"), want, 0o600); err != nil {
		t.Fatalf("seed live dir: %v", err)
	}

	t.Setenv(LiveDirEnv, dir)
	got, err := FS()
	if err != nil {
		t.Fatalf("FS() returned error: %v", err)
	}
	data, err := fs.ReadFile(got, "index.html")
	if err != nil {
		t.Fatalf("read index.html from live FS: %v", err)
	}
	if string(data) != string(want) {
		t.Fatalf("live FS served wrong bytes: got %q want %q", data, want)
	}
}

func TestFS_LiveDirOverrideReflectsRewrites(t *testing.T) {
	// Property the dev workflow depends on: an FS opened once must observe
	// later writes to the underlying directory. Without this, a server boot
	// that reads index.html once would never see `task build:ui` rebuilds.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("v1"), 0o600); err != nil {
		t.Fatalf("seed v1: %v", err)
	}
	t.Setenv(LiveDirEnv, dir)

	live, err := FS()
	if err != nil {
		t.Fatalf("FS() returned error: %v", err)
	}
	first, err := fs.ReadFile(live, "index.html")
	if err != nil {
		t.Fatalf("read v1: %v", err)
	}
	if string(first) != "v1" {
		t.Fatalf("first read got %q want v1", first)
	}

	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("v2"), 0o600); err != nil {
		t.Fatalf("seed v2: %v", err)
	}
	second, err := fs.ReadFile(live, "index.html")
	if err != nil {
		t.Fatalf("read v2: %v", err)
	}
	if string(second) != "v2" {
		t.Fatalf("second read got %q want v2 (FS not honoring on-disk rewrites)", second)
	}
}
