package bundle

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/internal/build"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/internal/testutil"
	"code-intelligence.com/cifuzz/pkg/artifact"
	"code-intelligence.com/cifuzz/pkg/cmdutils"
	"code-intelligence.com/cifuzz/pkg/dependencies"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/util/fileutil"
)

// A library in a system library directory that is not certain to exist in the Docker image.
const uncommonSystemDepUnix = "/usr/lib/libBLAS.so"

var testOut io.ReadWriter

// An external library in a non-system location.
var externalDep = generateExternalDepPath()

func generateExternalDepPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	return filepath.Join(home, ".conan", "cache", "libfoo.so")
}

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

func TestUnknownBuildSystem(t *testing.T) {
	_, err := cmdutils.ExecuteCommand(t, New(config.NewConfig()), os.Stdin)
	require.Error(t, err)
}

func TestAssembleArtifacts(t *testing.T) {
	seedCorpus, err := os.MkdirTemp("", "seed-corpus-*")
	require.NoError(t, err)
	defer fileutil.Cleanup(seedCorpus)
	err = fileutil.Touch(filepath.Join(seedCorpus, "seed"))
	require.NoError(t, err)

	// The project dir path has to be absolute, but doesn't have to exist.
	projectDir, err := filepath.Abs("project")
	require.NoError(t, err)

	fuzzTest := "some_fuzz_test"
	buildDir := filepath.Join(projectDir, "build")
	runtimeDeps := []string{
		// A library in the project's build directory.
		filepath.Join(buildDir, "lib", "helper.so"),
		externalDep,
	}
	if runtime.GOOS != "windows" {
		runtimeDeps = append(runtimeDeps, uncommonSystemDepUnix)
	}
	buildResult := &build.Result{
		Executable:  filepath.Join(buildDir, "pkg", fuzzTest),
		SeedCorpus:  seedCorpus,
		BuildDir:    buildDir,
		Engine:      "libfuzzer",
		Sanitizers:  []string{"address"},
		RuntimeDeps: runtimeDeps,
	}

	c := &bundleCmd{opts: &bundleOpts{}}
	fuzzers, manifest, systemDeps, err := c.assembleArtifacts(fuzzTest, buildResult, projectDir)
	require.NoError(t, err)

	require.Equal(t, 1, len(fuzzers))
	assert.Equal(t, artifact.Fuzzer{
		Target:        "some_fuzz_test",
		Path:          filepath.Join("libfuzzer", "address", "some_fuzz_test", "bin", "pkg", "some_fuzz_test"),
		Engine:        "LIBFUZZER",
		Sanitizer:     "ADDRESS",
		ProjectDir:    projectDir,
		Seeds:         filepath.Join("libfuzzer", "address", "some_fuzz_test", "seeds"),
		LibraryPaths:  []string{filepath.Join("libfuzzer", "address", "some_fuzz_test", "external_libs")},
		EngineOptions: artifact.EngineOptions{Env: []string{"NO_CIFUZZ=1"}},
	}, *fuzzers[0])

	assert.Equal(t, map[string]string{
		filepath.Join("libfuzzer", "address", "some_fuzz_test", "bin", "pkg", "some_fuzz_test"): filepath.Join(buildDir, "pkg", "some_fuzz_test"),
		filepath.Join("libfuzzer", "address", "some_fuzz_test", "bin", "lib", "helper.so"):      filepath.Join(buildDir, "lib", "helper.so"),
		filepath.Join("libfuzzer", "address", "some_fuzz_test", "external_libs", "libfoo.so"):   externalDep,
		filepath.Join("libfuzzer", "address", "some_fuzz_test", "seeds"):                        seedCorpus,
		filepath.Join("libfuzzer", "address", "some_fuzz_test", "seeds", "seed"):                filepath.Join(seedCorpus, "seed"),
	}, manifest)

	if runtime.GOOS != "windows" {
		assert.Equal(t, []string{uncommonSystemDepUnix}, systemDeps)
	}
}

func TestClangMissing(t *testing.T) {
	deps := dependencies.CreateTestDeps(t, []dependencies.Key{
		dependencies.CLANG, dependencies.CMAKE,
	})
	dependencies.OverwriteInstalledWithFalse(deps[dependencies.CLANG])

	conf := config.NewConfig()
	conf.BuildSystem = config.BuildSystemCMake

	// clone the example project because this command needs to parse an actual
	// project config... if there is none it will fail before the dependency check
	testDir, err := testutil.ChdirToClonedCmakeExampleProject("run-cmd-test")
	require.NoError(t, err)
	defer fileutil.Cleanup(testDir)

	_, err = cmdutils.ExecuteCommand(t, New(conf), os.Stdin)
	require.Error(t, err)

	output, err := io.ReadAll(testOut)
	require.NoError(t, err)
	assert.Contains(t, string(output), fmt.Sprintf(dependencies.MESSAGE_MISSING, "clang"))
}

func TestClangVersion(t *testing.T) {
	deps := dependencies.CreateTestDeps(t, []dependencies.Key{
		dependencies.CLANG, dependencies.CMAKE,
	})

	dep := deps[dependencies.CLANG]
	version := dependencies.OverwriteGetVersionWith0(dep)

	conf := config.NewConfig()
	conf.BuildSystem = config.BuildSystemCMake

	// clone the example project because this command needs to parse an actual
	// project config... if there is none it will fail before the dependency check
	testDir, err := testutil.ChdirToClonedCmakeExampleProject("run-cmd-test")
	require.NoError(t, err)
	defer fileutil.Cleanup(testDir)

	_, err = cmdutils.ExecuteCommand(t, New(conf), os.Stdin)
	require.Error(t, err)

	output, err := io.ReadAll(testOut)
	require.NoError(t, err)
	assert.Contains(t, string(output),
		fmt.Sprintf(dependencies.MESSAGE_VERSION, "clang", dep.MinVersion.String(), version))
}

func TestCMakeMissing(t *testing.T) {
	deps := dependencies.CreateTestDeps(t, []dependencies.Key{
		dependencies.CLANG, dependencies.CMAKE,
	})
	dependencies.OverwriteInstalledWithFalse(deps[dependencies.CMAKE])

	conf := config.NewConfig()
	conf.BuildSystem = config.BuildSystemCMake

	// clone the example project because this command needs to parse an actual
	// project config... if there is none it will fail before the dependency check
	testDir, err := testutil.ChdirToClonedCmakeExampleProject("run-cmd-test")
	require.NoError(t, err)
	defer fileutil.Cleanup(testDir)

	_, err = cmdutils.ExecuteCommand(t, New(conf), os.Stdin)
	require.Error(t, err)

	output, err := io.ReadAll(testOut)
	require.NoError(t, err)
	assert.Contains(t, string(output), fmt.Sprintf(dependencies.MESSAGE_MISSING, "cmake"))
}
