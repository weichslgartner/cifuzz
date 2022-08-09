package dependencies

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

func TestResetDefault(t *testing.T) {
	oldDefault := Default
	Default = Dependencies{}
	ResetDefaultsForTestsOnly()
	assert.Len(t, Default, 5)

	newKeys := maps.Keys(Default)
	for key, _ := range oldDefault {
		assert.Contains(t, newKeys, key)
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
