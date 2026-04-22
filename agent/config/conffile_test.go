package config

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfFile_HappyPath(t *testing.T) {
	body := strings.NewReader(`# Set by the install script.
EDR_SERVER_URL=https://edr.example.com
EDR_ENROLL_SECRET=pilot-secret

# quoted value keeps inner whitespace
EDR_LOG_LEVEL="debug"
  EDR_LOG_FORMAT = text
edr_server_fingerprint = sha256/abc123
`)
	m := parseConfFile(body, "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	assert.Equal(t, "https://edr.example.com", m["EDR_SERVER_URL"])
	assert.Equal(t, "pilot-secret", m["EDR_ENROLL_SECRET"])
	assert.Equal(t, "debug", m["EDR_LOG_LEVEL"])
	assert.Equal(t, "text", m["EDR_LOG_FORMAT"])
	assert.Equal(t, "sha256/abc123", m["EDR_SERVER_FINGERPRINT"],
		"keys are upper-cased so lookup matches os.Getenv")
}

func TestParseConfFile_MalformedSkipped(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	body := strings.NewReader("EDR_OK=1\nbogus-no-equals\n=missing_key\nEDR_OK2=2\n")

	m := parseConfFile(body, "test", logger)
	assert.Equal(t, "1", m["EDR_OK"])
	assert.Equal(t, "2", m["EDR_OK2"])
	assert.NotContains(t, m, "")
	assert.Contains(t, buf.String(), "skipping malformed line",
		"a malformed line must produce a warn log so operators can find it")
}

func TestLoadConfFile_MissingIsEmpty(t *testing.T) {
	// A missing conf file is expected on fresh installs before MDM writes anything.
	// Must return empty map without logging — error logs for ENOENT would spam the
	// startup log every boot.
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	m := loadConfFile(filepath.Join(t.TempDir(), "does-not-exist.conf"), logger)
	assert.Empty(t, m)
	assert.Empty(t, buf.String(), "ENOENT must not produce a warn log")
}

func TestLoadConfFile_PermErrorLogged(t *testing.T) {
	// A file that exists but cannot be read (chmod 0000) must log a warn and return
	// an empty map so the agent still boots — the operator just won't have the
	// conf-file-sourced defaults.
	dir := t.TempDir()
	path := filepath.Join(dir, "forbidden.conf")
	require.NoError(t, os.WriteFile(path, []byte("EDR_OK=1"), 0o000))

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	m := loadConfFile(path, logger)
	assert.Empty(t, m)
	if os.Geteuid() != 0 {
		// root bypasses the 0o000 permission so the log only appears for non-root.
		assert.Contains(t, buf.String(), "conf file open failed")
	}
}

func TestLayeredGetenv_EnvWinsOverConf(t *testing.T) {
	t.Setenv("EDR_LAYERED_TEST", "from-env")
	confMap := map[string]string{"EDR_LAYERED_TEST": "from-conf", "EDR_FROM_CONF_ONLY": "conf-only"}
	get := layeredGetenv(confMap)
	assert.Equal(t, "from-env", get("EDR_LAYERED_TEST"))
	assert.Equal(t, "conf-only", get("EDR_FROM_CONF_ONLY"))
	assert.Empty(t, get("EDR_NOT_ANYWHERE"))
}

func TestLayeredGetenv_EmptyEnvStillBeatsConf(t *testing.T) {
	// Explicit empty env is a valid operator choice ("clear this value"). Env wins
	// via os.LookupEnv so the conf-file default does not reassert itself.
	t.Setenv("EDR_LAYERED_EMPTY", "")
	confMap := map[string]string{"EDR_LAYERED_EMPTY": "from-conf"}
	get := layeredGetenv(confMap)
	assert.Empty(t, get("EDR_LAYERED_EMPTY"),
		"explicit empty env var must defeat the conf-file default")
}

func TestLoad_ConfFileProvidesDefaults(t *testing.T) {
	// End-to-end: writing a conf file and pointing Load at it via EDR_CONF_FILE
	// must populate the agent Config with values drawn from the file.
	dir := t.TempDir()
	confPath := filepath.Join(dir, "fleet-edr.conf")
	require.NoError(t, os.WriteFile(confPath, []byte(
		"EDR_SERVER_URL=https://edr.conf.example\nEDR_ENROLL_SECRET=conf-secret\nEDR_ALLOW_INSECURE=0\n",
	), 0o600))

	t.Setenv("EDR_CONF_FILE", confPath)
	// Clear any inherited env that would mask conf values.
	for _, k := range []string{"EDR_SERVER_URL", "EDR_ENROLL_SECRET", "EDR_ALLOW_INSECURE"} {
		t.Setenv(k, "")
		_ = os.Unsetenv(k)
	}

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "https://edr.conf.example", cfg.ServerURL)
	assert.Equal(t, "conf-secret", cfg.EnrollSecret)
}
