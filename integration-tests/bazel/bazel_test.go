package bazel

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/integration-tests/shared"
	builderPkg "code-intelligence.com/cifuzz/internal/builder"
	"code-intelligence.com/cifuzz/internal/testutil"
	"code-intelligence.com/cifuzz/pkg/parser/libfuzzer/stacktrace"
	"code-intelligence.com/cifuzz/util/envutil"
	"code-intelligence.com/cifuzz/util/fileutil"
)

func TestIntegration_Bazel_InitCreateRunBundle(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	if runtime.GOOS == "windows" {
		t.Skip("Using cifuzz with bazel is currently only supported on Unix")
	}

	// TODO: Fix this test on macOS
	if runtime.GOOS == "darwin" {
		t.Skip("Building with bazel is currently broken on our macOS GitHub Action runner")
	}

	testutil.RegisterTestDepOnCIFuzz()

	// Install cifuzz
	installDir := shared.InstallCIFuzzInTemp(t)
	cifuzz := builderPkg.CIFuzzExecutablePath(filepath.Join(installDir, "bin"))

	// Copy testdata
	dir := shared.CopyTestdataDir(t, "bazel")
	defer fileutil.Cleanup(dir)
	t.Logf("executing bazel integration test in %s", dir)

	cifuzzRunner := shared.CIFuzzRunner{
		CIFuzzPath:      cifuzz,
		DefaultWorkDir:  dir,
		DefaultFuzzTest: "//src/parser:parser_fuzz_test",
	}

	// Execute the init command
	linesToAdd := cifuzzRunner.Command(t, "init", nil)
	// Append the lines to WORKSPACE
	shared.AppendLines(t, filepath.Join(dir, "WORKSPACE"), linesToAdd)

	// Execute the create command
	outputPath := filepath.Join("src", "parser", "parser_fuzz_test.cpp")
	linesToAdd = cifuzzRunner.Command(t, "create", &shared.CommandOptions{
		Args: []string{"cpp", "--output", outputPath}},
	)

	// Check that the fuzz test was created in the correct directory
	fuzzTestPath := filepath.Join(dir, outputPath)
	require.FileExists(t, fuzzTestPath)

	// Append the lines to BUILD.bazel
	shared.AppendLines(t, filepath.Join(dir, "src", "parser", "BUILD.bazel"), linesToAdd)

	// Check that the findings command doesn't list any findings yet
	findings := shared.GetFindings(t, cifuzz, dir)
	require.Empty(t, findings)

	// Run the (empty) fuzz test
	cifuzzRunner.Run(t, &shared.RunOptions{
		ExpectedOutputs:              []*regexp.Regexp{regexp.MustCompile(`^paths: \d+`)},
		TerminateAfterExpectedOutput: true,
	})

	// Make the fuzz test call a function
	shared.ModifyFuzzTestToCallFunction(t, fuzzTestPath)

	// Add dependency on parser lib to BUILD.bazel
	cmd := exec.Command("buildozer", "add deps :parser", "//src/parser:parser_fuzz_test")
	cmd.Dir = dir
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	require.NoError(t, err)

	// Run the fuzz test and check that it finds the use-after-free
	expectedOutputs := []*regexp.Regexp{
		// Check that the use-after-free is found
		regexp.MustCompile(`^==\d*==ERROR: AddressSanitizer: heap-use-after-free`),
	}

	// Check that Minijail is used (if running on Linux, because Minijail
	// is only supported on Linux)
	if runtime.GOOS == "linux" {
		expectedOutputs = append(expectedOutputs, regexp.MustCompile(`bin/minijail0`))
	}

	// Run the fuzz test with and verify check that it finds the heap
	// buffer overflow
	cifuzzRunner.Run(t, &shared.RunOptions{ExpectedOutputs: expectedOutputs})

	// Check that the findings command lists the findings
	findings = shared.GetFindings(t, cifuzz, dir)
	// On Windows, only the ASan finding is expected, on Linux and macOS
	// at least two findings are expected
	require.Equal(t, len(findings), 1)
	asanFinding := findings[0]

	// TODO: This check currently fails on macOS because there
	// llvm-symbolizer doesn't read debug info from object files.
	// See https://github.com/google/sanitizers/issues/207#issuecomment-136495556
	if runtime.GOOS != "darwin" {
		expectedStackTrace := []*stacktrace.StackFrame{
			{
				SourceFile:  "src/parser/parser.cpp",
				Line:        23,
				Column:      14,
				FrameNumber: 0,
				Function:    "parse",
			},
			{
				SourceFile:  "src/parser/parser_fuzz_test.cpp",
				Line:        20,
				Column:      3,
				FrameNumber: 1,
				Function:    "LLVMFuzzerTestOneInputNoReturn",
			},
		}
		if runtime.GOOS == "windows" {
			// On Windows, the column is not printed
			for i := range expectedStackTrace {
				expectedStackTrace[i].Column = 0
			}
		}
		require.Equal(t, expectedStackTrace, asanFinding.StackTrace)
	}

	// Check that ASAN_OPTIONS can be set
	env, err := envutil.Setenv(os.Environ(), "ASAN_OPTIONS", "print_stats=1:atexit=1")
	require.NoError(t, err)
	cifuzzRunner.Run(t, &shared.RunOptions{
		Args:                         []string{"--recover-ubsan"},
		Env:                          env,
		ExpectedOutputs:              []*regexp.Regexp{regexp.MustCompile(`Stats:`)},
		TerminateAfterExpectedOutput: false,
	})

	// Run cifuzz bundle and verify the contents of the archive.
	shared.TestBundle(t, dir, cifuzz, "//src/parser:parser_fuzz_test")

	// The remote-run command is currently only supported on Linux
	if runtime.GOOS == "linux" {
		shared.TestRemoteRun(t, dir, cifuzz, "//src/parser:parser_fuzz_test")
	}
}
