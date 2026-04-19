// Package config loads and validates environment-based configuration for the EDR server.
//
// Every required var is checked at startup; missing or malformed values produce an error
// that names the offending variable. Optional vars fall back to sensible defaults.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the resolved server configuration.
type Config struct {
	DSN               string
	ListenAddr        string
	EnrollSecret      string
	TLSCertFile       string
	TLSKeyFile        string
	AllowInsecureHTTP bool
	AllowTLS12        bool
	EnrollRatePerMin  int
	LoginRatePerMin   int
	LogLevel          string
	LogFormat         string
	ProcessInterval   time.Duration
	ProcessBatch      int

	// Phase 4: data lifecycle + observability.
	//
	// RetentionDays is the age cap for events in days. 0 disables the retention
	// runner entirely (useful for operators who ship events to another store and
	// don't want MVP's default 30-day window). Default 30.
	RetentionDays int
	// RetentionInterval is how often the retention runner wakes up. Default 1h.
	RetentionInterval time.Duration

	// LaunchAgentAllowlist is the set of plist paths the `persistence_launchagent` rule
	// should silently accept. Populated from EDR_LAUNCHAGENT_ALLOWLIST (comma-separated
	// absolute paths). Empty by default — every plist load fires.
	LaunchAgentAllowlist map[string]struct{}
}

// TLSEnabled reports whether TLS cert and key are both set.
func (c Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

// Defaults returns a Config populated with default values. Callers should overlay env vars on top.
func defaults() Config {
	return Config{
		ListenAddr:        ":8088",
		LogLevel:          "info",
		LogFormat:         "json",
		ProcessInterval:   500 * time.Millisecond,
		ProcessBatch:      500,
		EnrollRatePerMin:  30,
		LoginRatePerMin:   6,
		RetentionDays:     30,
		RetentionInterval: time.Hour,
	}
}

// Load reads configuration from the environment. It returns an error aggregating every validation
// problem so the operator can fix all of them at once rather than playing whack-a-mole.
func Load() (*Config, error) {
	return loadFrom(os.Getenv)
}

// loadFrom is the testable core of Load; it takes a lookup function so tests can provide a fake env.
func loadFrom(getenv func(string) string) (*Config, error) {
	c := defaults()
	var errs []error

	requireStr(&c.DSN, "EDR_DSN", getenv, &errs, true)
	optionalStr(&c.ListenAddr, "EDR_LISTEN_ADDR", getenv)
	requireStr(&c.EnrollSecret, "EDR_ENROLL_SECRET", getenv, &errs, true)
	// Phase 3 removed EDR_ADMIN_TOKEN. UI + admin surfaces now authenticate via the
	// session cookie minted by POST /api/v1/session. The first-boot seeder prints the
	// admin password once so the operator can log in.
	optionalStr(&c.TLSCertFile, "EDR_TLS_CERT_FILE", getenv)
	optionalStr(&c.TLSKeyFile, "EDR_TLS_KEY_FILE", getenv)

	c.AllowInsecureHTTP = getenv("EDR_ALLOW_INSECURE_HTTP") == "1"
	c.AllowTLS12 = getenv("EDR_TLS_ALLOW_TLS12") == "1"

	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		errs = append(errs, errors.New(
			"EDR_TLS_CERT_FILE and EDR_TLS_KEY_FILE must be set together (or both left unset)"))
	}

	// Phase 1 requires TLS in production. The opt-out is deliberately noisy so operators
	// don't accidentally ship plaintext.
	if !c.TLSEnabled() && !c.AllowInsecureHTTP {
		errs = append(errs, errors.New(
			"EDR_TLS_CERT_FILE is required (set EDR_ALLOW_INSECURE_HTTP=1 for dev)"))
	}

	parsePositiveInt(getenv, "EDR_ENROLL_RATE_PER_MIN", &c.EnrollRatePerMin, &errs)
	parsePositiveInt(getenv, "EDR_LOGIN_RATE_PER_MIN", &c.LoginRatePerMin, &errs)
	// Phase 4: retention window. Allow 0 to disable entirely. Negative = error.
	parseNonNegativeInt(getenv, "EDR_RETENTION_DAYS", &c.RetentionDays, &errs)
	parsePositiveDuration(getenv, "EDR_RETENTION_INTERVAL", &c.RetentionInterval, &errs)

	if v := getenv("EDR_LAUNCHAGENT_ALLOWLIST"); v != "" {
		c.LaunchAgentAllowlist = parseAllowlist(v)
	}

	if v := getenv("EDR_LOG_LEVEL"); v != "" {
		// Normalize to the canonical lowercase form so downstream slog handlers see one of the
		// documented values regardless of how the operator spelled it (e.g. "INFO", "Warn").
		c.LogLevel = strings.ToLower(v)
	}
	if !validLogLevel(c.LogLevel) {
		errs = append(errs, fmt.Errorf("EDR_LOG_LEVEL=%q must be one of debug, info, warn, error", c.LogLevel))
	}

	if v := getenv("EDR_LOG_FORMAT"); v != "" {
		c.LogFormat = strings.ToLower(v)
	}
	if c.LogFormat != "json" && c.LogFormat != "text" {
		errs = append(errs, fmt.Errorf("EDR_LOG_FORMAT=%q must be 'json' or 'text'", c.LogFormat))
	}

	// processor.Run feeds ProcessInterval into time.NewTicker, which panics on non-positive values.
	parsePositiveDuration(getenv, "EDR_PROCESS_INTERVAL", &c.ProcessInterval, &errs)
	parsePositiveInt(getenv, "EDR_PROCESS_BATCH", &c.ProcessBatch, &errs)

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return &c, nil
}

// parsePositiveInt reads key from the env, parses it as an int, requires it to be > 0,
// and writes to *dst. Errors are appended to *errs; an unset key is a no-op (defaults
// win).
func parsePositiveInt(getenv func(string) string, key string, dst *int, errs *[]error) {
	v := getenv(key)
	if v == "" {
		return
	}
	n, err := strconv.Atoi(v)
	switch {
	case err != nil:
		*errs = append(*errs, fmt.Errorf("%s=%q: %w", key, v, err))
	case n <= 0:
		*errs = append(*errs, fmt.Errorf("%s=%d must be positive", key, n))
	default:
		*dst = n
	}
}

// parseNonNegativeInt is like parsePositiveInt but permits 0 (used for "disabled"
// sentinels such as retention-days=0).
func parseNonNegativeInt(getenv func(string) string, key string, dst *int, errs *[]error) {
	v := getenv(key)
	if v == "" {
		return
	}
	n, err := strconv.Atoi(v)
	switch {
	case err != nil:
		*errs = append(*errs, fmt.Errorf("%s=%q: %w", key, v, err))
	case n < 0:
		*errs = append(*errs, fmt.Errorf("%s=%d must be >= 0 (0 disables)", key, n))
	default:
		*dst = n
	}
}

// parsePositiveDuration reads key as a Go duration and requires it to be > 0.
func parsePositiveDuration(getenv func(string) string, key string, dst *time.Duration, errs *[]error) {
	v := getenv(key)
	if v == "" {
		return
	}
	d, err := time.ParseDuration(v)
	switch {
	case err != nil:
		*errs = append(*errs, fmt.Errorf("%s=%q: %w", key, v, err))
	case d <= 0:
		*errs = append(*errs, fmt.Errorf("%s=%q must be positive", key, v))
	default:
		*dst = d
	}
}

// parseAllowlist turns a comma-separated string into a set, trimming whitespace and
// dropping empty entries.
func parseAllowlist(v string) map[string]struct{} {
	out := make(map[string]struct{})
	for p := range strings.SplitSeq(v, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out[p] = struct{}{}
	}
	return out
}

func requireStr(dst *string, key string, getenv func(string) string, errs *[]error, nonEmpty bool) {
	v := getenv(key)
	if v == "" && nonEmpty {
		*errs = append(*errs, fmt.Errorf("required env var %s is not set", key))
		return
	}
	*dst = v
}

func optionalStr(dst *string, key string, getenv func(string) string) {
	if v := getenv(key); v != "" {
		*dst = v
	}
}

func validLogLevel(lvl string) bool {
	switch strings.ToLower(lvl) {
	case "debug", "info", "warn", "error":
		return true
	}
	return false
}
