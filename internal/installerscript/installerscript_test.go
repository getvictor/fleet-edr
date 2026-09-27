package installerscript

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLocate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		args        []string
		script, pkg string
	}{
		{"a compiled script is argv[0]", []string{"/tmp/PKInstallSandbox.a/Scripts/b/postinstall", "/p.pkg", "/", "/", "/"},
			"/tmp/PKInstallSandbox.a/Scripts/b/postinstall", "/p.pkg"},
		{"a script behind an interpreter is argv[1]", []string{"/bin/sh", "/tmp/PKInstallSandbox.a/Scripts/b/preinstall", "/p.pkg"},
			"/tmp/PKInstallSandbox.a/Scripts/b/preinstall", "/p.pkg"},
		{"nothing follows the script", []string{"/tmp/PKInstallSandbox.a/Scripts/b/postinstall"}, "", ""},
		{"a script outside the sandbox", []string{"/bin/bash", "/tmp/other/postinstall", "/p.pkg"}, "", ""},
		{"no argv", nil, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			script, pkg := Locate(tc.args)
			assert.Equal(t, tc.script, script)
			assert.Equal(t, tc.pkg, pkg)
		})
	}
}
