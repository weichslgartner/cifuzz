package cmake

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/integration-tests/shared"
	builderPkg "code-intelligence.com/cifuzz/internal/builder"
	"code-intelligence.com/cifuzz/internal/testutil"
	"code-intelligence.com/cifuzz/pkg/finding"
	"code-intelligence.com/cifuzz/pkg/parser/libfuzzer/stacktrace"
	"code-intelligence.com/cifuzz/util/envutil"
	"code-intelligence.com/cifuzz/util/executil"
	"code-intelligence.com/cifuzz/util/fileutil"
)

func TestIntegration_CMake_InitCreateRunCoverageBundle(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	testutil.RegisterTestDepOnCIFuzz()

	// Create installation builder
	installDir := shared.InstallCIFuzzInTemp(t)
	cifuzz := builderPkg.CIFuzzExecutablePath(filepath.Join(installDir, "bin"))
	err := os.Setenv("CMAKE_PREFIX_PATH", installDir)
	require.NoError(t, err)

	// Copy testdata
	dir := shared.CopyTestdataDir(t, "cmake")
	defer fileutil.Cleanup(dir)
	t.Logf("executing cmake integration test in %s", dir)

	cifuzzRunner := shared.CIFuzzRunner{
		CIFuzzPath:      cifuzz,
		DefaultWorkDir:  dir,
		DefaultFuzzTest: "parser_fuzz_test",
	}

	// Execute the root command
	cifuzzRunner.Command(t, "", nil)

	// Execute the init command
	linesToAdd := cifuzzRunner.Command(t, "init", nil)
	shared.AddLinesToFileAtBreakPoint(t, filepath.Join(dir, "CMakeLists.txt"), linesToAdd, "add_subdirectory", false)

	// Execute the create command
	outputPath := filepath.Join("src", "parser", "parser_fuzz_test.cpp")
	linesToAdd = cifuzzRunner.Command(t, "create", &shared.CommandOptions{
		Args: []string{"cpp", "--output", outputPath}},
	)

	// Check that the fuzz test was created in the correct directory
	fuzzTestPath := filepath.Join(dir, outputPath)
	require.FileExists(t, fuzzTestPath)

	// Append the lines to CMakeLists.txt
	shared.AppendLines(t, filepath.Join(filepath.Dir(fuzzTestPath), "CMakeLists.txt"), linesToAdd)

	// Check that the findings command doesn't list any findings yet
	findings := shared.GetFindings(t, cifuzz, dir)
	require.Empty(t, findings)

	// Run the (empty) fuzz test
	cifuzzRunner.Run(t, &shared.RunOptions{
		ExpectedOutputs:              []*regexp.Regexp{regexp.MustCompile(`^paths: \d+`)},
		TerminateAfterExpectedOutput: true,
	})

	// Make the fuzz test call a function. Before we do that, we sleep
	// for one second, to avoid make implementations which only look at
	// the full seconds of the timestamp to not rebuild the target, see
	// https://www.gnu.org/software/autoconf/manual/autoconf-2.63/html_node/Timestamps-and-Make.html
	time.Sleep(time.Second)
	shared.ModifyFuzzTestToCallFunction(t, fuzzTestPath)

	// Add dependency on parser lib to CMakeLists.txt
	cmakeLists := filepath.Join(filepath.Dir(fuzzTestPath), "CMakeLists.txt")
	shared.AppendLines(t, cmakeLists, []string{"target_link_libraries(parser_fuzz_test PRIVATE parser)"})

	// Run the fuzz test and check that it finds the undefined behavior
	// (unless we're running on Windows, in which case UBSan is not
	// supported)
	if runtime.GOOS != "windows" {
		expectedOutputs := []*regexp.Regexp{
			regexp.MustCompile(`^SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior`),
		}
		cifuzzRunner.Run(t, &shared.RunOptions{ExpectedOutputs: expectedOutputs})
	}

	expectedOutputs := []*regexp.Regexp{
		// Check that the use-after-free is found
		regexp.MustCompile(`^==\d*==ERROR: AddressSanitizer: heap-use-after-free`),
	}

	// Check that Minijail is used (if running on Linux, because Minijail
	// is only supported on Linux)
	if runtime.GOOS == "linux" {
		minijailOutDir := filepath.Join(os.TempDir(), "minijail-out")
		expectedOutputs = append(expectedOutputs, regexp.MustCompile(regexp.QuoteMeta(`artifact_prefix='`+minijailOutDir)))
	}

	// Run the fuzz test with --recover-ubsan and verify that it now
	// also finds the heap buffer overflow
	cifuzzRunner.Run(t, &shared.RunOptions{
		Args:            []string{"--recover-ubsan"},
		ExpectedOutputs: expectedOutputs,
	})

	// Check that the findings command lists the findings
	findings = shared.GetFindings(t, cifuzz, dir)
	// On Windows, only the ASan finding is expected, on Linux and macOS
	// at least two findings are expected
	require.GreaterOrEqual(t, len(findings), 1)
	var asanFinding *finding.Finding
	for _, f := range findings {
		if strings.HasPrefix(f.Details, "heap-use-after-free") {
			asanFinding = f
		}
	}
	require.NotNil(t, asanFinding)
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

	// Check that options set via the config file are respected
	configFileContent := `use-sandbox: false`
	err = os.WriteFile(filepath.Join(dir, "cifuzz.yaml"), []byte(configFileContent), 0644)
	require.NoError(t, err)
	// Check that Minijail is not used (i.e. the artifact prefix is
	// not set to the Minijail output path)
	expectedOutputs = []*regexp.Regexp{
		regexp.MustCompile(regexp.QuoteMeta(`artifact_prefix='` + filepath.Join(os.TempDir(), "libfuzzer-out"))),
	}
	cifuzzRunner.Run(t, &shared.RunOptions{ExpectedOutputs: expectedOutputs})

	if runtime.GOOS == "linux" {
		// Check that command-line flags take precedence over config file
		// settings (only on Linux because we only support Minijail on
		// Linux).
		cifuzzRunner.Run(t, &shared.RunOptions{
			Args:            []string{"--use-sandbox=true"},
			ExpectedOutputs: []*regexp.Regexp{regexp.MustCompile(`minijail`)},
		})
	}
	// Clear cifuzz.yml so that subsequent tests run with defaults (e.g. sandboxing).
	err = os.WriteFile(filepath.Join(dir, "cifuzz.yaml"), nil, 0644)
	require.NoError(t, err)

	// Check that ASAN_OPTIONS can be set
	env, err := envutil.Setenv(os.Environ(), "ASAN_OPTIONS", "print_stats=1:atexit=1")
	require.NoError(t, err)
	cifuzzRunner.Run(t, &shared.RunOptions{
		Args:                         []string{"--recover-ubsan"},
		Env:                          env,
		ExpectedOutputs:              []*regexp.Regexp{regexp.MustCompile(`Stats:`)},
		TerminateAfterExpectedOutput: false,
	})

	// Building with coverage instrumentation doesn't work on Windows yet
	if runtime.GOOS != "windows" {
		// Produce a coverage report for parser_fuzz_test
		createHtmlCoverageReport(t, cifuzz, dir)
		// Produces a coverage report for crashing_fuzz_test
		createAndVerifyLcovCoverageReport(t, cifuzz, dir)
	}

	// Run cifuzz bundle and verify the contents of the archive.
	shared.TestBundle(t, dir, cifuzz, "parser_fuzz_test")

	// The remote-run command is currently only supported on Linux
	if runtime.GOOS == "linux" {
		shared.TestRemoteRun(t, dir, cifuzz)
	}

}

func createHtmlCoverageReport(t *testing.T, cifuzz string, dir string) {
	t.Helper()

	cmd := executil.Command(cifuzz, "coverage", "-v",
		"--output", "parser_fuzz_test.coverage.html",
		"parser_fuzz_test")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	require.NoError(t, err)

	// Check that the coverage report was created
	reportPath := filepath.Join(dir, "parser_fuzz_test.coverage.html")
	require.FileExists(t, reportPath)

	// Check that the coverage report contains coverage for the
	// parser.cpp source file, but not for our headers.
	reportBytes, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	report := string(reportBytes)
	require.Contains(t, report, "parser.cpp")
	require.NotContains(t, report, "include/cifuzz")
}

func createAndVerifyLcovCoverageReport(t *testing.T, cifuzz string, dir string) {
	t.Helper()

	reportPath := filepath.Join(dir, "crashing_fuzz_test.lcov")

	cmd := executil.Command(cifuzz, "coverage", "-v",
		"--format=lcov",
		"--output", reportPath,
		"crashing_fuzz_test")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	require.NoError(t, err)

	// Check that the coverage report was created
	require.FileExists(t, reportPath)

	// Read the report and extract all uncovered lines in the fuzz test source file.
	reportBytes, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	lcov := bufio.NewScanner(bytes.NewBuffer(reportBytes))
	isFuzzTestSource := false
	var uncoveredLines []uint
	for lcov.Scan() {
		line := lcov.Text()

		if strings.HasPrefix(line, "SF:") {
			if strings.HasSuffix(line, "/coverage/crashing_fuzz_test.cpp") {
				isFuzzTestSource = true
			} else {
				isFuzzTestSource = false
				assert.Fail(t, "Unexpected source file: "+line)
			}
		}

		if !isFuzzTestSource || !strings.HasPrefix(line, "DA:") {
			continue
		}
		split := strings.Split(strings.TrimPrefix(line, "DA:"), ",")
		require.Len(t, split, 2)
		if split[1] == "0" {
			lineNo, err := strconv.Atoi(split[0])
			require.NoError(t, err)
			uncoveredLines = append(uncoveredLines, uint(lineNo))
		}
	}

	assert.Subset(t, []uint{
		// Lines after the three crashes. Whether these are covered depends on implementation details of the coverage
		// instrumentation, so we conservatively assume they aren't covered.
		21, 31, 41},
		uncoveredLines)
}
