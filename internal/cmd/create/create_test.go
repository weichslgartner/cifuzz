package create

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

func TestOk(t *testing.T) {
	testDir, err := testutil.ChdirToClonedCmakeExampleProject("create-cmd-test")
	require.NoError(t, err)
	defer fileutil.Cleanup(testDir)

	args := []string{
		"cpp",
		"--output",
		filepath.Join(testDir, "fuzz-test.cpp"),
	}
	_, err = cmdutils.ExecuteCommand(t, New(config.NewConfig()), os.Stdin, args...)
	assert.NoError(t, err)
}

func TestInvalidType(t *testing.T) {
	args := []string{
		"foo",
	}
	_, err := cmdutils.ExecuteCommand(t, New(config.NewConfig()), os.Stdin, args...)
	assert.Error(t, err)
}

func TestCreateCmd_OutDir(t *testing.T) {
	t.Skip()
}

func TestCMakeMissing(t *testing.T) {
	deps := dependencies.CreateTestDeps(t, []dependencies.Key{dependencies.CLANG, dependencies.CMAKE})
	dependencies.OverwriteInstalledWithFalse(deps[dependencies.CMAKE])

	testDir, err := testutil.ChdirToClonedCmakeExampleProject("create-cmd-test")
	require.NoError(t, err)
	defer fileutil.Cleanup(testDir)
	args := []string{
		"cpp",
		"--output",
		filepath.Join(testDir, "fuzz-test.cpp"),
	}

	conf := config.NewConfig()
	conf.BuildSystem = config.BuildSystemCMake

	_, err = cmdutils.ExecuteCommand(t, New(conf), os.Stdin, args...)
	// should not fail as this command has no hard dependencies, just recommendations
	require.NoError(t, err)

	output, err := io.ReadAll(testOut)
	require.NoError(t, err)
	assert.Contains(t, string(output), fmt.Sprintf(dependencies.MESSAGE_MISSING, "cmake"))
}

func TestClangVersion(t *testing.T) {
	deps := dependencies.CreateTestDeps(t, []dependencies.Key{dependencies.CLANG, dependencies.CMAKE})

	dep := deps[dependencies.CLANG]
	version := dependencies.OverwriteGetVersionWith0(dep)

	testDir, err := testutil.ChdirToClonedCmakeExampleProject("create-cmd-test")
	require.NoError(t, err)
	defer fileutil.Cleanup(testDir)
	args := []string{
		"cpp",
		"--output",
		filepath.Join(testDir, "fuzz-test.cpp"),
	}

	conf := config.NewConfig()
	conf.BuildSystem = config.BuildSystemCMake

	_, err = cmdutils.ExecuteCommand(t, New(conf), os.Stdin, args...)
	// should not fail as this command has no hard dependencies, just recommendations
	require.NoError(t, err)

	output, err := io.ReadAll(testOut)
	require.NoError(t, err)
	assert.Contains(t, string(output),
		fmt.Sprintf(dependencies.MESSAGE_VERSION, "clang", dep.MinVersion.String(), version))
}
