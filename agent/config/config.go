// Package config loads agent configuration from the environment. No flag-based fallback is
// provided; environment variables are the only supported configuration surface. Every
// recognised variable is validated at startup and every invalid value produces an error that
// names the offending variable.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fleetdm/edr/internal/envparse"
)

const (
	defaultXPCService    = "8VBZ3948LU.com.fleetdm.edr.securityextension.xpc"
	defaultNetXPCService = "group.com.fleetdm.edr.networkextension"
	defaultQueueDBPath   = "/var/db/fleet-edr/events.db"
)

// Config is the resolved agent configuration.
type Config struct {
	ServerURL         string
	EnrollSecret      string
	TokenFile         string
	ServerFingerprint string
	HostIDOverride    string
	QueueDBPath       string
	QueueMaxBytes     int64 // EDR_AGENT_QUEUE_MAX_BYTES; default 500 MiB, 0 = unbounded
	XPCService        string
	NetXPCService     string
	BatchSize         int
	UploadInterval    time.Duration
	PruneAge          time.Duration
	LogLevel          string
	LogFormat         string
	AllowInsecure     bool
}

// Load reads configuration from the environment and validates it.
func Load() (*Config, error) {
	return loadFrom(os.Getenv)
}

func loadFrom(getenv func(string) string) (*Config, error) {
	//nolint:gosec // "enrolled.plist" is a path, not a credential.
	c := Config{
		TokenFile:      "/var/db/fleet-edr/enrolled.plist",
		QueueDBPath:    defaultQueueDBPath,
		QueueMaxBytes:  500 * 1024 * 1024, // 500 MiB soft cap; 0 via env disables.
		XPCService:     defaultXPCService,
		NetXPCService:  defaultNetXPCService,
		BatchSize:      100,
		UploadInterval: time.Second,
		PruneAge:       24 * time.Hour,
		LogLevel:       "info",
		LogFormat:      "json",
	}
	var errs []error

	c.ServerURL = strings.TrimSpace(getenv("EDR_SERVER_URL"))
	if c.ServerURL == "" {
		errs = append(errs, errors.New("required env var EDR_SERVER_URL is not set"))
	}

	c.EnrollSecret = getenv("EDR_ENROLL_SECRET")
	optional(&c.TokenFile, "EDR_TOKEN_FILE", getenv)
	optional(&c.ServerFingerprint, "EDR_SERVER_FINGERPRINT", getenv)

	c.AllowInsecure = getenv("EDR_ALLOW_INSECURE") == "1"
	if c.ServerURL != "" {
		validateServerURL(c.ServerURL, c.AllowInsecure, &errs)
	}

	optional(&c.HostIDOverride, "EDR_HOST_ID", getenv)
	optional(&c.QueueDBPath, "EDR_QUEUE_DB_PATH", getenv)
	optional(&c.XPCService, "EDR_XPC_SERVICE", getenv)
	optional(&c.NetXPCService, "EDR_NET_XPC_SERVICE", getenv)

	envparse.PositiveInt(getenv, "EDR_BATCH_SIZE", &c.BatchSize, &errs)
	// uploader.Run feeds UploadInterval into time.NewTicker, which panics on non-positive values.
	envparse.PositiveDuration(getenv, "EDR_UPLOAD_INTERVAL", &c.UploadInterval, &errs)
	// A zero or negative prune age computes a future cutoff and deletes nearly every uploaded
	// row; outright reject.
	envparse.PositiveDuration(getenv, "EDR_PRUNE_AGE", &c.PruneAge, &errs)
	// EDR_AGENT_QUEUE_MAX_BYTES: positive int for cap, 0 to disable. Default 500 MiB
	// is set above and applies when the env var is unset; setting it explicitly to 0
	// restores the pre-Phase-4 unbounded behaviour for benchmarking or recovery.
	envparse.NonNegativeInt64(getenv, "EDR_AGENT_QUEUE_MAX_BYTES", &c.QueueMaxBytes, &errs)

	if v := getenv("EDR_LOG_LEVEL"); v != "" {
		// Normalize to canonical lowercase so downstream slog handlers see one of the documented
		// values regardless of case.
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

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return &c, nil
}

func optional(dst *string, key string, getenv func(string) string) {
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

// validateServerURL rejects typos, missing schemes, case variants ("HTTP://..."), and
// unsupported schemes such as "ws://" that would slip past a naive prefix match.
func validateServerURL(serverURL string, allowInsecure bool, errs *[]error) {
	u, err := url.Parse(serverURL)
	if err != nil || u.Host == "" {
		*errs = append(*errs, fmt.Errorf("EDR_SERVER_URL=%q must be a valid http(s) URL", serverURL))
		return
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		// ok
	case "http":
		if !allowInsecure {
			*errs = append(*errs, errors.New(
				"EDR_SERVER_URL uses http://; set EDR_ALLOW_INSECURE=1 for dev or use an https:// URL"))
		}
	default:
		*errs = append(*errs, fmt.Errorf("EDR_SERVER_URL=%q must use http or https", serverURL))
	}
}
