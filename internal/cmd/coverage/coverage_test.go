package coverage

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

func TestFail(t *testing.T) {
	_, err := cmdutils.ExecuteCommand(t, New(), os.Stdin)
	assert.Error(t, err)
}

func TestClangMissing(t *testing.T) {
	deps := dependencies.CreateTestDeps(t, []dependencies.Key{
		dependencies.CLANG, dependencies.LLVM_SYMBOLIZER, dependencies.LLVM_COV, dependencies.LLVM_PROFDATA, dependencies.CMAKE,
	})
	dependencies.OverwriteInstalledWithFalse(deps[dependencies.CLANG])

	// clone the example project because this command needs to parse an actual
	// project config... if there is none it will fail before the dependency check
	testDir, err := testutil.BootstrapExampleProjectForTest("coverage-cmd-test", config.BuildSystemCMake)
	require.NoError(t, err)
	defer fileutil.Cleanup(testDir)

	_, err = cmdutils.ExecuteCommand(t, New(), os.Stdin, "my_fuzz_test")
	require.Error(t, err)

	output, err := io.ReadAll(testOut)
	require.NoError(t, err)
	assert.Contains(t, string(output), fmt.Sprintf(dependencies.MESSAGE_MISSING, "clang"))
}

func TestCMakeMissing(t *testing.T) {
	deps := dependencies.CreateTestDeps(t, []dependencies.Key{
		dependencies.CLANG, dependencies.LLVM_SYMBOLIZER, dependencies.LLVM_COV, dependencies.LLVM_PROFDATA, dependencies.CMAKE,
	})
	dependencies.OverwriteInstalledWithFalse(deps[dependencies.CMAKE])

	// clone the example project because this command needs to parse an actual
	// project config... if there is none it will fail before the dependency check
	testDir, err := testutil.BootstrapExampleProjectForTest("coverage-cmd-test", config.BuildSystemCMake)
	require.NoError(t, err)
	defer fileutil.Cleanup(testDir)

	_, err = cmdutils.ExecuteCommand(t, New(), os.Stdin, "my_fuzz_test")
	fmt.Println(err)
	require.Error(t, err)

	output, err := io.ReadAll(testOut)
	require.NoError(t, err)
	assert.Contains(t, string(output), fmt.Sprintf(dependencies.MESSAGE_MISSING, "cmake"))
}

func TestLlvmCovVersion(t *testing.T) {
	deps := dependencies.CreateTestDeps(t, []dependencies.Key{
		dependencies.CLANG, dependencies.LLVM_SYMBOLIZER, dependencies.LLVM_COV, dependencies.LLVM_PROFDATA, dependencies.CMAKE,
	})

	dep := deps[dependencies.LLVM_COV]
	version := dependencies.OverwriteGetVersionWith0(dep)

	// clone the example project because this command needs to parse an actual
	// project config... if there is none it will fail before the dependency check
	testDir, err := testutil.BootstrapExampleProjectForTest("coverage-cmd-test", config.BuildSystemCMake)
	require.NoError(t, err)
	defer fileutil.Cleanup(testDir)

	_, err = cmdutils.ExecuteCommand(t, New(), os.Stdin, "my_fuzz_test")
	fmt.Println(err)
	require.Error(t, err)

	output, err := io.ReadAll(testOut)
	require.NoError(t, err)
	assert.Contains(t, string(output),
		fmt.Sprintf(dependencies.MESSAGE_VERSION, "llvm-cov", dep.MinVersion.String(), version))
}
