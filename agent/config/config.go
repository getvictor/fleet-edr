// Package config loads agent configuration from the environment. See claude/mvp/phase-0-foundation.md
// for the full variable reference. No flag-based fallback is provided; a clean env is the only
// supported configuration surface.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultXPCService    = "8VBZ3948LU.com.fleetdm.edr.securityextension.xpc"
	defaultNetXPCService = "group.com.fleetdm.edr.networkextension"
	defaultQueueDBPath   = "/var/db/fleet-edr/events.db"
)

// Config is the resolved agent configuration.
type Config struct {
	ServerURL      string
	BearerToken    string
	HostIDOverride string
	QueueDBPath    string
	XPCService     string
	NetXPCService  string
	BatchSize      int
	UploadInterval time.Duration
	PruneAge       time.Duration
	LogLevel       string
	LogFormat      string
	AllowInsecure  bool
}

// Load reads configuration from the environment and validates it.
func Load() (*Config, error) {
	return loadFrom(os.Getenv)
}

func loadFrom(getenv func(string) string) (*Config, error) {
	c := Config{
		QueueDBPath:    defaultQueueDBPath,
		XPCService:     defaultXPCService,
		NetXPCService:  defaultNetXPCService,
		BatchSize:      100,
		UploadInterval: time.Second,
		PruneAge:       24 * time.Hour,
		LogLevel:       "info",
		LogFormat:      "json",
	}
	var errs []error

	c.ServerURL = getenv("EDR_SERVER_URL")
	if c.ServerURL == "" {
		errs = append(errs, errors.New("required env var EDR_SERVER_URL is not set"))
	}

	c.BearerToken = getenv("EDR_BEARER_TOKEN")
	if c.BearerToken == "" {
		errs = append(errs, errors.New("required env var EDR_BEARER_TOKEN is not set"))
	}

	c.AllowInsecure = getenv("EDR_ALLOW_INSECURE") == "1"
	if strings.HasPrefix(c.ServerURL, "http://") && !c.AllowInsecure {
		errs = append(errs, errors.New("EDR_SERVER_URL uses http://; set EDR_ALLOW_INSECURE=1 for dev or use an https:// URL"))
	}

	optional(&c.HostIDOverride, "EDR_HOST_ID", getenv)
	optional(&c.QueueDBPath, "EDR_QUEUE_DB_PATH", getenv)
	optional(&c.XPCService, "EDR_XPC_SERVICE", getenv)
	optional(&c.NetXPCService, "EDR_NET_XPC_SERVICE", getenv)

	if v := getenv("EDR_BATCH_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("EDR_BATCH_SIZE=%q: %w", v, err))
		} else if n <= 0 {
			errs = append(errs, fmt.Errorf("EDR_BATCH_SIZE=%d must be positive", n))
		} else {
			c.BatchSize = n
		}
	}

	if v := getenv("EDR_UPLOAD_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("EDR_UPLOAD_INTERVAL=%q: %w", v, err))
		} else {
			c.UploadInterval = d
		}
	}

	if v := getenv("EDR_PRUNE_AGE"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("EDR_PRUNE_AGE=%q: %w", v, err))
		} else {
			c.PruneAge = d
		}
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
