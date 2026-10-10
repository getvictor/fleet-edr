package arch_test

// macos_floor_test holds the installer's macOS minimum and the Xcode deployment target in step. They live in different files and
// nothing else reads both: the app and extensions were once built for 26.2 while the installer still accepted 13, so a Mac on 13
// through 26.1 installed the package and then could not launch it (ADR-0002, 2026-10-10 amendment).

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	deploymentTargetRE = regexp.MustCompile(`MACOSX_DEPLOYMENT_TARGET = ([0-9.]+);`)
	installerMinRE     = regexp.MustCompile(`<os-version min="([0-9.]+)"/>`)
	volumeCheckMajorRE = regexp.MustCompile(`major < ([0-9]+)\)`)
)

// spec:release-packaging/the-installer-refuses-a-macos-the-bundles-cannot-run-on/the-installer-minimum-matches-the-deployment-target
// spec:release-packaging/the-installer-refuses-a-macos-the-bundles-cannot-run-on/an-older-mac-is-refused-with-the-requirement-named
func TestMacOSFloor_InstallerMatchesDeploymentTarget(t *testing.T) {
	t.Parallel()
	root := repoRootFromTest(t)

	pbxproj, err := os.ReadFile(filepath.Join(root, "extension", "edr", "edr.xcodeproj", "project.pbxproj"))
	require.NoError(t, err)
	targets := deploymentTargetRE.FindAllStringSubmatch(string(pbxproj), -1)
	require.NotEmpty(t, targets, "the Xcode project sets no MACOSX_DEPLOYMENT_TARGET")
	deploymentTarget := targets[0][1]
	for _, m := range targets {
		assert.Equal(t, deploymentTarget, m[1], "every build configuration must share one deployment target")
	}

	distribution, err := os.ReadFile(filepath.Join(root, "packaging", "pkg", "distribution.xml"))
	require.NoError(t, err)
	installerMin := installerMinRE.FindStringSubmatch(string(distribution))
	require.NotNil(t, installerMin, "distribution.xml declares no <os-version min>")
	assert.Equal(t, deploymentTarget, installerMin[1],
		"the installer minimum must equal the deployment target, or a Mac between them installs a package it cannot run")

	// volumeCheck() is the scripted gate that names the requirement to the user; it compares majors only, so it must refuse
	// every major below the deployment target's.
	check := volumeCheckMajorRE.FindStringSubmatch(string(distribution))
	require.NotNil(t, check, "distribution.xml's volumeCheck() no longer compares the macOS major version")
	wantMajor, err := strconv.Atoi(strings.SplitN(deploymentTarget, ".", 2)[0])
	require.NoError(t, err)
	gotMajor, err := strconv.Atoi(check[1])
	require.NoError(t, err)
	assert.Equal(t, wantMajor, gotMajor, "volumeCheck() must refuse every macOS major below the deployment target's")
	assert.Contains(t, string(distribution), "requires macOS "+strconv.Itoa(wantMajor)+" ",
		"the refusal must name the macOS version the package needs")
}
