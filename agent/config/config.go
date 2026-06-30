// Package config loads agent configuration from the environment. No flag-based fallback is provided; environment variables are the
// only supported configuration surface. Every recognised variable is validated at startup and every invalid value produces an error
// that names the offending variable.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fleetdm/edr/internal/envparse"
)

const (
	defaultXPCService = "FDG8Q7N4CC.com.fleetdm.edr.securityextension.xpc"
	// The network extension's only launchd-registered Mach service is its NEMachServiceName, which Apple requires to be
	// app-group-scoped. A team-prefixed name is NOT registered for a NetworkExtension sysext (unlike the security
	// extension, which gets its team-prefixed name registered via NSEndpointSecurityMachServiceName), so dialing one
	// fails at the Mach bootstrap lookup with "xpc_bridge_connect failed". The agent reaches the app-group name fine
	// (verified on edr-qa: "receiver connected" to group.com.fleetdm.edr.networkextension across many sessions). #300
	// switched this to a team-prefixed name on a false premise and silently broke NE event delivery.
	defaultNetXPCService = "group.com.fleetdm.edr.networkextension"
	defaultQueueDBPath   = "/var/db/fleet-edr/events.db"

	// DefaultPruneAge drops uploaded events older than 24h from the local SQLite queue. Wired into the prune loop at boot (no longer
	// an env knob).
	DefaultPruneAge = 24 * time.Hour

	// defaultProcessReconcileInterval is the default for EDR_PROCESS_RECONCILE_INTERVAL: how often the agent sweeps its proctable for
	// missed exit events. 60s tracks the server's freshness reconciler but is closer to ground truth on a single host.
	defaultProcessReconcileInterval = 60 * time.Second

	// DefaultQueueMaxBytes is the soft cap for the agent's SQLite queue (500 MiB). Wired into the queue at boot (no longer an env knob).
	DefaultQueueMaxBytes = 500 * 1024 * 1024

	// DefaultNetworkCoalesceWindow is the window over which the agent collapses repetitive network_connect / dns_query telemetry into
	// one representative event before enqueue (issue #408). 10s cuts most repetitive chatter while staying well under the 30s
	// DNS-to-connect beacon-correlation window, so a representative can never be pushed outside it; that invariant is why the window is
	// a fixed constant rather than an operator knob. Wired into the coalescer at boot.
	DefaultNetworkCoalesceWindow = 10 * time.Second

	// DefaultBatchSize is the upload batch size. Wired into the uploader at boot (no longer an env knob).
	DefaultBatchSize = 100

	// DefaultUploadInterval is how often the uploader drains the queue to the server. Wired into the uploader at boot (no longer an
	// env knob).
	DefaultUploadInterval = time.Second
)

// Config is the resolved agent configuration.
type Config struct {
	ServerURL         string
	EnrollSecret      string
	TokenFile         string
	ServerFingerprint string
	// ControlAddr is the server's reachable control-channel gRPC endpoint, e.g. "edr.example.com:8090" (the server's address, not a
	// bind literal like ":8090"). Empty (default) keeps the agent on the GET /api/commands short-poll; set EDR_CONTROL_ADDR to open the
	// persistent push stream (the poll then becomes the fallback floor). From #477.
	ControlAddr              string
	HostIDOverride           string
	QueueDBPath              string
	XPCService               string
	NetXPCService            string
	ProcessReconcileInterval time.Duration // EDR_PROCESS_RECONCILE_INTERVAL; default 60s, 0 disables.
	LogLevel                 string
	LogFormat                string
	AllowInsecure            bool
}

// Load reads configuration from the environment and validates it. The environment is layered on top of /etc/fleet-edr.conf (override
// path via EDR_CONF_FILE for dev and tests) so the MDM-managed conf file sets baseline values and operator-scoped env vars override a
// single host without editing the file. Missing or malformed entries in the conf file are logged and the load continues with env-only
// values.
//
// Load is the production wiring boundary: the only place that reaches into the process environment. Tests bypass it and call
// loadFromEnv directly with fakes so the suite stays parallel-safe (issue #179).
func Load() (*Config, error) {
	return loadFromEnv(os.Getenv, os.LookupEnv) //nolint:forbidigo // approved agent-config boundary; see issue #179
}

// loadFromEnv is the testable core of Load: it reads EDR_CONF_FILE, loads the conf file, and builds the layered getenv. Tests inject
// fakes for getenv + lookupEnv so they can drive every code path without touching the process environment.
func loadFromEnv(getenv func(string) string, lookupEnv LookupEnvFunc) (*Config, error) {
	confPath := getenv("EDR_CONF_FILE")
	if confPath == "" {
		confPath = DefaultConfFile
	}
	confMap := loadConfFile(confPath, slog.Default())
	return loadFrom(layeredGetenv(confMap, lookupEnv))
}

func loadFrom(getenv func(string) string) (*Config, error) {
	//nolint:gosec // "enrolled.plist" is a path, not a credential.
	c := Config{
		TokenFile:                "/var/db/fleet-edr/enrolled.plist",
		QueueDBPath:              defaultQueueDBPath,
		XPCService:               defaultXPCService,
		NetXPCService:            defaultNetXPCService,
		ProcessReconcileInterval: defaultProcessReconcileInterval,
		LogLevel:                 "info",
		LogFormat:                "json",
	}
	var errs []error

	c.ServerURL = strings.TrimSpace(getenv("EDR_SERVER_URL"))
	if c.ServerURL == "" {
		errs = append(errs, errors.New("required env var EDR_SERVER_URL is not set"))
	}

	c.EnrollSecret = getenv("EDR_ENROLL_SECRET")
	optional(&c.TokenFile, "EDR_TOKEN_FILE", getenv)
	optional(&c.ServerFingerprint, "EDR_SERVER_FINGERPRINT", getenv)
	optional(&c.ControlAddr, "EDR_CONTROL_ADDR", getenv)

	c.AllowInsecure = getenv("EDR_ALLOW_INSECURE") == "1"
	if c.ServerURL != "" {
		validateServerURL(c.ServerURL, c.AllowInsecure, &errs)
	}

	optional(&c.HostIDOverride, "EDR_HOST_ID", getenv)
	optional(&c.QueueDBPath, "EDR_QUEUE_DB_PATH", getenv)
	optional(&c.XPCService, "EDR_XPC_SERVICE", getenv)
	optional(&c.NetXPCService, "EDR_NET_XPC_SERVICE", getenv)

	// 0 disables the agent-side process-tree reconciliation loop entirely (issue #6 client half): useful for narrow QA where synthetic
	// exits would distort what a clean ESF feed looks like. Negative values are rejected.
	envparse.NonNegativeDuration(getenv, "EDR_PROCESS_RECONCILE_INTERVAL", &c.ProcessReconcileInterval, &errs)

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
