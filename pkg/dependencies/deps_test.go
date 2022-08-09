package dependencies

import (
	"errors"
	"testing"

	"github.com/Masterminds/semver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/pkg/mocks"
)

func TestCheck(t *testing.T) {
	keys := []Key{CLANG}
	deps, err := Define(keys)
	require.NoError(t, err)

	dep := deps[CLANG]
	dep.GetVersion = func(d *Dependency) (*semver.Version, error) {
		return &d.MinVersion, nil
	}

	finder := &mocks.RunfilesFinderMock{}
	finder.On("ClangPath").Return("clang", nil)

	result, err := Check(keys, deps, finder)
	require.NoError(t, err)
	assert.True(t, result)
}

func TestCheck_NotInstalled(t *testing.T) {
	keys := []Key{CLANG}
	deps, err := Define(keys)
	require.NoError(t, err)

	finder := &mocks.RunfilesFinderMock{}
	finder.On("ClangPath").Return("", errors.New("missing-error"))

	result, err := Check(keys, deps, finder)
	require.NoError(t, err)
	assert.False(t, result)
}

func TestCheck_WrongVersion(t *testing.T) {
	keys := []Key{CLANG}
	deps, err := Define(keys)
	require.NoError(t, err)

	// overwrite GetVersion for clang
	dep := deps[CLANG]
	dep.GetVersion = func(d *Dependency) (*semver.Version, error) {
		return semver.MustParse("1.0.0"), nil
	}

	finder := &mocks.RunfilesFinderMock{}
	finder.On("ClangPath").Return("clang", nil)

	result, err := Check(keys, deps, finder)
	require.NoError(t, err)
	assert.False(t, result)
}

func TestCheck_ShortVersion(t *testing.T) {
	keys := []Key{CLANG}
	deps, err := Define(keys)
	require.NoError(t, err)

	// overwrite GetVersion for clang
	dep := deps[CLANG]
	dep.GetVersion = func(d *Dependency) (*semver.Version, error) {
		return semver.MustParse("11.0"), nil
	}

	finder := &mocks.RunfilesFinderMock{}
	finder.On("ClangPath").Return("clang", nil)

	result, err := Check(keys, deps, finder)
	require.NoError(t, err)
	assert.True(t, result)
}

func TestCheck_UnableToGetVersion(t *testing.T) {
	keys := []Key{CLANG}
	deps, err := Define(keys)
	require.NoError(t, err)

	// overwrite GetVersion for clang
	dep := deps[CLANG]
	dep.GetVersion = func(d *Dependency) (*semver.Version, error) {
		return nil, errors.New("version-error")
	}

	finder := &mocks.RunfilesFinderMock{}
	finder.On("ClangPath").Return("clang", nil)

	result, err := Check(keys, deps, finder)
	require.NoError(t, err)

	// yes, this is right :) If there was an error while
	// detecting the version we assume it is most probably
	// a fail of your extraction mechanism
	assert.True(t, result)
}
