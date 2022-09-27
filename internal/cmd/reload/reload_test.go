package reload

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/dependencies"
	"code-intelligence.com/cifuzz/pkg/log"
)

var testOut io.ReadWriter

func TestMain(m *testing.M) {
	// capture log output
	testOut = bytes.NewBuffer([]byte{})
	oldOut := log.Output
	log.Output = testOut
	viper.Set("verbose", true)

	m.Run()

	log.Output = oldOut
	dependencies.ResetDefaultsForTestsOnly()
}

func TestOtherBuildSystem(t *testing.T) {
	_, err := cmdutils.ExecuteCommand(t, New(), os.Stdin)
	assert.Error(t, err)
}

func TestClangMissing(t *testing.T) {
	deps := dependencies.CreateTestDeps(t, []dependencies.Key{dependencies.CLANG, dependencies.CMAKE})
	dependencies.OverwriteInstalledWithFalse(deps[dependencies.CLANG])

	opts := &reloadOpts{
		BuildSystem: config.BuildSystemCMake,
	}

	_, err := cmdutils.ExecuteCommand(t, newWithOptions(opts), os.Stdin)
	require.Error(t, err)

	output, err := io.ReadAll(testOut)
	require.NoError(t, err)
	assert.Contains(t, string(output), fmt.Sprintf(dependencies.MESSAGE_MISSING, "clang"))
}

func TestCMakeMissing(t *testing.T) {
	deps := dependencies.CreateTestDeps(t, []dependencies.Key{dependencies.CLANG, dependencies.CMAKE})
	dependencies.OverwriteInstalledWithFalse(deps[dependencies.CMAKE])

	opts := &reloadOpts{
		BuildSystem: config.BuildSystemCMake,
	}

	_, err := cmdutils.ExecuteCommand(t, newWithOptions(opts), os.Stdin)
	require.Error(t, err)

	output, err := io.ReadAll(testOut)
	require.NoError(t, err)
	assert.Contains(t, string(output), fmt.Sprintf(dependencies.MESSAGE_MISSING, "cmake"))
}

func TestWrongCMakeVersion(t *testing.T) {
	deps := dependencies.CreateTestDeps(t, []dependencies.Key{dependencies.CLANG, dependencies.CMAKE})

	dep := deps[dependencies.CMAKE]
	version := dependencies.OverwriteGetVersionWith0(dep)

	opts := &reloadOpts{
		BuildSystem: config.BuildSystemCMake,
	}

	_, err := cmdutils.ExecuteCommand(t, newWithOptions(opts), os.Stdin)
	require.Error(t, err)

	output, err := io.ReadAll(testOut)
	require.NoError(t, err)
	assert.Contains(t, string(output),
		fmt.Sprintf(dependencies.MESSAGE_VERSION, "cmake", dep.MinVersion.String(), version))
}
