package dependencies

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

func TestResetDefault(t *testing.T) {
	oldDefaultCMake := CMakeDeps
	oldDefaultMaven := MavenDeps
	oldDefaultGradle := GradleDeps

	CMakeDeps = Dependencies{}
	MavenDeps = Dependencies{}
	GradleDeps = Dependencies{}

	ResetDefaultsForTestsOnly()
	assert.Len(t, CMakeDeps, 5)
	assert.Len(t, MavenDeps, 1)
	assert.Len(t, GradleDeps, 1)

	newCMakeKeys := maps.Keys(CMakeDeps)
	for key, _ := range oldDefaultCMake {
		assert.Contains(t, newCMakeKeys, key)
	}

	newMavenKeys := maps.Keys(MavenDeps)
	for key, _ := range oldDefaultMaven {
		assert.Contains(t, newMavenKeys, key)
	}

	newGradleKeys := maps.Keys(GradleDeps)
	for key, _ := range oldDefaultGradle {
		assert.Contains(t, newGradleKeys, key)
	}
}
func TestResetDefault_Panic(t *testing.T) {
	// remove clang from dep list
	clangDep := all[CLANG]
	delete(all, CLANG)

	assert.Panics(t, ResetDefaultsForTestsOnly)

	// restore old dependency
	all[CLANG] = clangDep
}

func TestDefine(t *testing.T) {
	deps, err := Define([]Key{CLANG})
	require.NoError(t, err)
	assert.Len(t, deps, 1)
	assert.Contains(t, maps.Keys(deps), CLANG)
}

func TestDefine_Error(t *testing.T) {
	// remove clang from dep list
	clangDep := all[CLANG]
	delete(all, CLANG)

	_, err := Define([]Key{CLANG})
	require.Error(t, err)

	// restore old dependency
	all[CLANG] = clangDep
}
