package bundler

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/internal/build"
	"code-intelligence.com/cifuzz/pkg/artifact"
	"code-intelligence.com/cifuzz/util/fileutil"
)

// A library in a system library directory that is not certain to exist in the Docker image.
const uncommonSystemDepUnix = "/usr/lib/libBLAS.so"

// An external library in a non-system location.
var externalDep = generateExternalDepPath()

func generateExternalDepPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	return filepath.Join(home, ".conan", "cache", "libfoo.so")
}

func TestAssembleArtifacts_Fuzzing(t *testing.T) {
	seedCorpus, err := os.MkdirTemp("", "seed-corpus-*")
	require.NoError(t, err)
	defer fileutil.Cleanup(seedCorpus)
	tempDir, err := os.MkdirTemp("", "bundle-*")
	require.NoError(t, err)
	defer fileutil.Cleanup(tempDir)
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
		Name:        fuzzTest,
		Executable:  filepath.Join(buildDir, "pkg", fuzzTest),
		SeedCorpus:  seedCorpus,
		BuildDir:    buildDir,
		Engine:      "libfuzzer",
		Sanitizers:  []string{"address"},
		RuntimeDeps: runtimeDeps,
		ProjectDir:  projectDir,
	}

	b := NewBundler(&Opts{
		Env: []string{"FOO=foo"},
	})
	b.tempDir = tempDir
	fuzzers, manifest, systemDeps, err := b.assembleArtifacts(buildResult)
	require.NoError(t, err)

	require.Equal(t, 1, len(fuzzers))
	require.Equal(t, artifact.Fuzzer{
		Target:        "some_fuzz_test",
		Path:          filepath.Join("libfuzzer", "address", "some_fuzz_test", "bin", "pkg", "some_fuzz_test"),
		Engine:        "LIBFUZZER",
		Sanitizer:     "ADDRESS",
		ProjectDir:    projectDir,
		Seeds:         filepath.Join("libfuzzer", "address", "some_fuzz_test", "seeds"),
		LibraryPaths:  []string{filepath.Join("libfuzzer", "address", "some_fuzz_test", "external_libs")},
		EngineOptions: artifact.EngineOptions{Env: []string{"FOO=foo", "NO_CIFUZZ=1"}},
	}, *fuzzers[0])

	require.Equal(t, map[string]string{
		filepath.Join("libfuzzer", "address", "some_fuzz_test", "bin", "pkg", "some_fuzz_test"):             filepath.Join(buildDir, "pkg", "some_fuzz_test"),
		filepath.Join("libfuzzer", "address", "some_fuzz_test", "bin", "lib", "helper.so"):                  filepath.Join(buildDir, "lib", "helper.so"),
		filepath.Join("libfuzzer", "address", "some_fuzz_test", "external_libs", "libfoo.so"):               externalDep,
		filepath.Join("libfuzzer", "address", "some_fuzz_test", "seeds", filepath.Base(seedCorpus)):         seedCorpus,
		filepath.Join("libfuzzer", "address", "some_fuzz_test", "seeds", filepath.Base(seedCorpus), "seed"): filepath.Join(seedCorpus, "seed"),
	}, manifest)

	if runtime.GOOS != "windows" {
		require.Equal(t, []string{uncommonSystemDepUnix}, systemDeps)
	}
}

func TestAssembleArtifacts_Coverage(t *testing.T) {
	seedCorpus, err := os.MkdirTemp("", "seed-corpus-*")
	require.NoError(t, err)
	defer fileutil.Cleanup(seedCorpus)
	tempDir, err := os.MkdirTemp("", "bundle-*")
	require.NoError(t, err)
	defer fileutil.Cleanup(tempDir)
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
		Name:        fuzzTest,
		Executable:  filepath.Join(buildDir, "pkg", fuzzTest),
		SeedCorpus:  seedCorpus,
		BuildDir:    buildDir,
		Engine:      "libfuzzer",
		Sanitizers:  []string{"coverage"},
		RuntimeDeps: runtimeDeps,
		ProjectDir:  projectDir,
	}

	c := NewBundler(&Opts{})
	c.tempDir = tempDir
	fuzzers, manifest, systemDeps, err := c.assembleArtifacts(buildResult)
	require.NoError(t, err)

	require.Equal(t, 1, len(fuzzers))
	assert.Equal(t, artifact.Fuzzer{
		Target:       "some_fuzz_test",
		Path:         filepath.Join("replayer", "coverage", "some_fuzz_test", "bin", "pkg", "some_fuzz_test"),
		Engine:       "LLVM_COV",
		ProjectDir:   projectDir,
		Seeds:        filepath.Join("replayer", "coverage", "some_fuzz_test", "seeds"),
		LibraryPaths: []string{filepath.Join("replayer", "coverage", "some_fuzz_test", "external_libs")},
		EngineOptions: artifact.EngineOptions{
			Env:   []string{"NO_CIFUZZ=1"},
			Flags: []string{"-merge=1", "."},
		},
	}, *fuzzers[0])

	assert.Equal(t, map[string]string{
		filepath.Join("replayer", "coverage", "some_fuzz_test", "bin", "pkg", "some_fuzz_test"):             filepath.Join(buildDir, "pkg", "some_fuzz_test"),
		filepath.Join("replayer", "coverage", "some_fuzz_test", "bin", "lib", "helper.so"):                  filepath.Join(buildDir, "lib", "helper.so"),
		filepath.Join("replayer", "coverage", "some_fuzz_test", "external_libs", "libfoo.so"):               externalDep,
		filepath.Join("replayer", "coverage", "some_fuzz_test", "seeds", filepath.Base(seedCorpus)):         seedCorpus,
		filepath.Join("replayer", "coverage", "some_fuzz_test", "seeds", filepath.Base(seedCorpus), "seed"): filepath.Join(seedCorpus, "seed"),
	}, manifest)

	if runtime.GOOS != "windows" {
		assert.Equal(t, []string{uncommonSystemDepUnix}, systemDeps)
	}
}
