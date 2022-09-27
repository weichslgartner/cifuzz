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
	"code-intelligence.com/cifuzz/internal/testutil"
	"code-intelligence.com/cifuzz/pkg/dependencies"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/util/fileutil"
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

func TestReloadCmd_FailsIfNoCIFuzzProject(t *testing.T) {
	// Create an empty directory
	projectDir, err := os.MkdirTemp("", "test-reload-cmd-fails-")
	require.NoError(t, err)
	defer fileutil.Cleanup(projectDir)

	opts := &options{
		ProjectDir: projectDir,
		ConfigDir:  projectDir,
	}

	// Check that the command produces the expected error when not
	// called below a cifuzz project directory.
	_, err = cmdutils.ExecuteCommand(t, newWithOptions(opts), os.Stdin)
	require.Error(t, err)
	testutil.CheckOutput(t, testOut, "Failed to parse cifuzz.yaml")
}

func TestClangMissing(t *testing.T) {
	projectDir := testutil.BootstrapEmptyProject(t, "test-reload-")
	opts := &options{
		ProjectDir:  projectDir,
		ConfigDir:   projectDir,
		BuildSystem: config.BuildSystemCMake,
	}

	deps := dependencies.CreateTestDeps(t, []dependencies.Key{dependencies.CLANG, dependencies.CMAKE})
	dependencies.OverwriteInstalledWithFalse(deps[dependencies.CLANG])

	_, err := cmdutils.ExecuteCommand(t, newWithOptions(opts), os.Stdin)
	require.Error(t, err)

	output, err := io.ReadAll(testOut)
	require.NoError(t, err)
	assert.Contains(t, string(output), fmt.Sprintf(dependencies.MESSAGE_MISSING, "clang"))
}

func TestCMakeMissing(t *testing.T) {
	projectDir := testutil.BootstrapEmptyProject(t, "test-reload-")
	opts := &options{
		ProjectDir:  projectDir,
		ConfigDir:   projectDir,
		BuildSystem: config.BuildSystemCMake,
	}

	deps := dependencies.CreateTestDeps(t, []dependencies.Key{dependencies.CLANG, dependencies.CMAKE})
	dependencies.OverwriteInstalledWithFalse(deps[dependencies.CMAKE])

	_, err := cmdutils.ExecuteCommand(t, newWithOptions(opts), os.Stdin)
	require.Error(t, err)

	output, err := io.ReadAll(testOut)
	require.NoError(t, err)
	assert.Contains(t, string(output), fmt.Sprintf(dependencies.MESSAGE_MISSING, "cmake"))
}

func TestWrongCMakeVersion(t *testing.T) {
	projectDir := testutil.BootstrapEmptyProject(t, "test-reload-")
	opts := &options{
		ProjectDir:  projectDir,
		ConfigDir:   projectDir,
		BuildSystem: config.BuildSystemCMake,
	}

	deps := dependencies.CreateTestDeps(t, []dependencies.Key{dependencies.CLANG, dependencies.CMAKE})
	dep := deps[dependencies.CMAKE]
	version := dependencies.OverwriteGetVersionWith0(dep)

	_, err := cmdutils.ExecuteCommand(t, newWithOptions(opts), os.Stdin)
	require.Error(t, err)

	output, err := io.ReadAll(testOut)
	require.NoError(t, err)
	assert.Contains(t, string(output),
		fmt.Sprintf(dependencies.MESSAGE_VERSION, "cmake", dep.MinVersion.String(), version))
}
