package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// fileBackedGetenv wraps an env lookup with Docker-secret-style `*_FILE`
// fallback: when `KEY` is unset or empty but `KEY_FILE` points at a readable
// file, the file's trimmed contents become the value of `KEY`. This lets
// operators stand up the server from a docker-compose stack that mounts
// secrets at /run/secrets/* without ever putting the raw value in a compose
// env block or a shell history.
//
// The wrapper is a plain decorator: every existing validator keeps calling
// getenv(KEY); it does not need to know the `_FILE` variant exists. Cycle
// detection is not needed because the wrapper only reads KEY_FILE for the
// original KEY, not recursively.
//
// Errors reading a `_FILE` path are logged and treated as "value unset" so
// the existing required-var validator then reports the canonical "required
// env var X is not set" rather than a less actionable read-file error.
func fileBackedGetenv(base func(string) string, logger *slog.Logger) func(string) string {
	if logger == nil {
		logger = slog.Default()
	}
	return func(key string) string {
		if v := base(key); v != "" {
			return v
		}
		path := base(key + "_FILE")
		if path == "" {
			return ""
		}
		data, err := os.ReadFile(path) //nolint:gosec // path supplied by operator via env.
		if err != nil {
			logger.WarnContext(context.Background(),
				"failed to read *_FILE env var; treating as unset",
				"key", key, "path", path, "err", err)
			return ""
		}
		return strings.TrimSpace(string(data))
	}
}

// WriteSecretFile is a tiny helper for tests and docker-compose fixtures: it
// writes the given value to a tempfile with 0600 perms and returns the path.
// Kept in the non-test file so integration tests that live outside the
// server/config package can reach it.
func WriteSecretFile(dir, name, value string) (string, error) {
	path := fmt.Sprintf("%s/%s", dir, name)
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		return "", err
	}
	return path, nil
}
