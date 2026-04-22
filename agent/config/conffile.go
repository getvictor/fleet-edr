package config

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
)

// DefaultConfFile is where the pkg installer drops the agent's static
// configuration. Fleet's install-script contract writes the enroll secret +
// server URL here before invoking `installer`; standalone deployments do the
// same by hand. Env vars always win over conf file entries so operators can
// override a single host without editing the file.
const DefaultConfFile = "/etc/fleet-edr.conf"

// loadConfFile parses a simple KEY=VALUE configuration file. Comments (lines
// starting with '#') and blank lines are ignored. Malformed lines are logged
// at warn level via logger and skipped; parsing does not abort on them. A
// missing file is not an error: callers get an empty map, falling back to env
// vars alone. Keys are upper-cased and trimmed for lookup parity with
// os.Getenv.
//
// The format is intentionally stdlib-only: no HOCON, no JSON, no variable
// interpolation. Every line is either a comment, blank, or of the form
// KEY=VALUE. Values may be surrounded by single or double quotes which are
// stripped; otherwise the value is taken verbatim, with leading + trailing
// whitespace trimmed.
func loadConfFile(path string, logger *slog.Logger) map[string]string {
	if logger == nil {
		logger = slog.Default()
	}
	f, err := os.Open(path) //nolint:gosec // path is operator-supplied config file.
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			logger.WarnContext(context.Background(),
				"conf file open failed; continuing with env-only config",
				"path", path, "err", err)
		}
		return map[string]string{}
	}
	defer f.Close()
	return parseConfFile(f, path, logger)
}

// parseConfFile is the pure-IO portion of loadConfFile. Split out for
// testability so tests can pass an in-memory reader instead of a tempfile.
func parseConfFile(r io.Reader, path string, logger *slog.Logger) map[string]string {
	out := map[string]string{}
	scanner := bufio.NewScanner(r)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		eq := strings.IndexByte(raw, '=')
		if eq <= 0 {
			logger.WarnContext(context.Background(),
				"conf file: skipping malformed line",
				"path", path, "line", lineNo, "reason", "missing '=' or empty key")
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(raw[:eq]))
		val := strings.TrimSpace(raw[eq+1:])
		// Strip matching outer single or double quotes so operators can quote
		// values containing '#' or leading whitespace without surprise.
		if len(val) >= 2 {
			first, last := val[0], val[len(val)-1]
			if (first == '"' || first == '\'') && first == last {
				val = val[1 : len(val)-1]
			}
		}
		out[key] = val
	}
	if err := scanner.Err(); err != nil {
		logger.WarnContext(context.Background(),
			"conf file: read error; returning partial map",
			"path", path, "err", err)
	}
	return out
}

// layeredGetenv returns a getenv-shaped function that consults the real
// environment first and falls back to the conf file map. Real env vars always
// win so operators can override one host without editing the file.
func layeredGetenv(confMap map[string]string) func(string) string {
	return func(key string) string {
		if v, ok := os.LookupEnv(key); ok {
			return v
		}
		return confMap[key]
	}
}
