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
	DSN             string
	ListenAddr      string
	BearerToken     string
	EnrollSecret    string
	TLSCertFile     string
	TLSKeyFile      string
	LogLevel        string
	LogFormat       string
	ProcessInterval time.Duration
	ProcessBatch    int
}

// TLSEnabled reports whether TLS cert and key are both set.
func (c Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

// Defaults returns a Config populated with default values. Callers should overlay env vars on top.
func defaults() Config {
	return Config{
		ListenAddr:      ":8088",
		LogLevel:        "info",
		LogFormat:       "json",
		ProcessInterval: 500 * time.Millisecond,
		ProcessBatch:    500,
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
	requireStr(&c.BearerToken, "EDR_BEARER_TOKEN", getenv, &errs, true)
	optionalStr(&c.EnrollSecret, "EDR_ENROLL_SECRET", getenv)
	optionalStr(&c.TLSCertFile, "EDR_TLS_CERT_FILE", getenv)
	optionalStr(&c.TLSKeyFile, "EDR_TLS_KEY_FILE", getenv)

	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		errs = append(errs, errors.New(
			"EDR_TLS_CERT_FILE and EDR_TLS_KEY_FILE must be set together (or both left unset)"))
	}

	if v := getenv("EDR_LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}
	if !validLogLevel(c.LogLevel) {
		errs = append(errs, fmt.Errorf("EDR_LOG_LEVEL=%q must be one of debug, info, warn, error", c.LogLevel))
	}

	if v := getenv("EDR_LOG_FORMAT"); v != "" {
		c.LogFormat = v
	}
	if c.LogFormat != "json" && c.LogFormat != "text" {
		errs = append(errs, fmt.Errorf("EDR_LOG_FORMAT=%q must be 'json' or 'text'", c.LogFormat))
	}

	if v := getenv("EDR_PROCESS_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("EDR_PROCESS_INTERVAL=%q: %w", v, err))
		} else {
			c.ProcessInterval = d
		}
	}

	if v := getenv("EDR_PROCESS_BATCH"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("EDR_PROCESS_BATCH=%q: %w", v, err))
		} else if n <= 0 {
			errs = append(errs, fmt.Errorf("EDR_PROCESS_BATCH=%d must be positive", n))
		} else {
			c.ProcessBatch = n
		}
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return &c, nil
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
