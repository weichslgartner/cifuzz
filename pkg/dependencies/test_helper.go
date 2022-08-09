package dependencies

import (
	"testing"

	"github.com/Masterminds/semver"
	"github.com/stretchr/testify/require"
)

// Creates a set of dependency mocks
// all dependcies are marked as "installed" and
// are present in just the right version by default
func CreateTestDeps(t *testing.T, keys []Key) Dependencies {
	t.Helper()
	deps, err := Define(keys)
	require.NoError(t, err)

	// mock functions
	versionFunc := func(dep *Dependency) (*semver.Version, error) {
		return &dep.MinVersion, nil
	}
	installedFunc := func(dep *Dependency) bool {
		return true
	}

	// this functions would look for/use the actual commands,
	// so they needed to be replaced with mocks
	for _, dep := range deps {
		dep.GetVersion = versionFunc
		dep.Installed = installedFunc
	}

	Default = deps
	return deps
}

// Replaces the `GetVersion` function with one that returns version 0.0.0
func OverwriteGetVersionWith0(dep *Dependency) *semver.Version {
	version := semver.MustParse("0.0.0")
	dep.GetVersion = func(d *Dependency) (*semver.Version, error) {
		return version, nil
	}
	return version
}

// Replaces the `Installed` function with one that returns false
func OverwriteInstalledWithFalse(dep *Dependency) {
	dep.Installed = func(d *Dependency) bool {
		return false
	}
}
