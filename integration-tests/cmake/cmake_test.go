package cmake

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

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

	// Execute the root command
	shared.RunCommand(t, dir, cifuzz, nil)

	// Execute the init command
	initOutput := shared.RunCommand(t, dir, cifuzz, []string{"init"})
	shared.AddLinesToFileAtBreakPoint(t, filepath.Join(dir, "CMakeLists.txt"), initOutput, "add_subdirectory", false)

	// Execute the create command
	outputPath := filepath.Join("src", "parser", "parser_fuzz_test.cpp")
	createOutput := shared.RunCommand(t, dir, cifuzz, []string{"create", "cpp", "--output", outputPath})

	// Check that the fuzz test was created in the correct directory
	fuzzTestPath := filepath.Join(dir, outputPath)
	require.FileExists(t, fuzzTestPath)

	// Append the lines to CMakeLists.txt
	f, err := os.OpenFile(filepath.Join(filepath.Dir(fuzzTestPath), "CMakeLists.txt"), os.O_APPEND|os.O_WRONLY, 0600)
	defer f.Close()
	require.NoError(t, err)
	for _, s := range createOutput {
		_, err = f.WriteString(s + "\n")
		require.NoError(t, err)
	}

	// Check that the findings command doesn't list any findings yet
	findings := shared.GetFindings(t, cifuzz, dir)
	require.Empty(t, findings)

	// Run the (empty) fuzz test
	runFuzzer(t, cifuzz, dir, &runFuzzerOptions{
		expectedOutputs:              []*regexp.Regexp{regexp.MustCompile(`^paths: \d+`)},
		terminateAfterExpectedOutput: true,
	})

	// Make the fuzz test call a function. Before we do that, we sleep
	// for one second, to avoid make implementations which only look at
	// the full seconds of the timestamp to not rebuild the target, see
	// https://www.gnu.org/software/autoconf/manual/autoconf-2.63/html_node/Timestamps-and-Make.html
	time.Sleep(time.Second)
	modifyFuzzTestToCallFunction(t, fuzzTestPath)

	// Run the fuzz test and check that it finds the undefined behavior
	// (unless we're running on Windows, in which case UBSan is not
	// supported)
	if runtime.GOOS != "windows" {
		expectedOutputs := []*regexp.Regexp{
			regexp.MustCompile(`^SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior`),
		}
		runFuzzer(t, cifuzz, dir, &runFuzzerOptions{expectedOutputs: expectedOutputs})
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
	runFuzzer(t, cifuzz, dir, &runFuzzerOptions{
		expectedOutputs: expectedOutputs,
		args:            []string{"--recover-ubsan"},
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
	runFuzzer(t, cifuzz, dir, &runFuzzerOptions{expectedOutputs: expectedOutputs})

	if runtime.GOOS == "linux" {
		// Check that command-line flags take precedence over config file
		// settings (only on Linux because we only support Minijail on
		// Linux).
		runFuzzer(t, cifuzz, dir, &runFuzzerOptions{
			expectedOutputs: []*regexp.Regexp{regexp.MustCompile(`minijail`)},
			args:            []string{"--use-sandbox=true"},
		})
	}
	// Clear cifuzz.yml so that subsequent tests run with defaults (e.g. sandboxing).
	err = os.WriteFile(filepath.Join(dir, "cifuzz.yaml"), nil, 0644)
	require.NoError(t, err)

	// Check that ASAN_OPTIONS can be set
	env, err := envutil.Setenv(os.Environ(), "ASAN_OPTIONS", "print_stats=1:atexit=1")
	require.NoError(t, err)
	runFuzzer(t, cifuzz, dir, &runFuzzerOptions{
		expectedOutputs:              []*regexp.Regexp{regexp.MustCompile(`Stats:`)},
		terminateAfterExpectedOutput: false,
		env:                          env,
		args:                         []string{"--recover-ubsan"},
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
		testRemoteRun(t, dir, cifuzz)
	}
}

type runFuzzerOptions struct {
	expectedOutputs              []*regexp.Regexp
	terminateAfterExpectedOutput bool
	env                          []string
	args                         []string
}

func runFuzzer(t *testing.T, cifuzz string, dir string, opts *runFuzzerOptions) {
	t.Helper()

	if opts.env == nil {
		opts.env = os.Environ()
	}

	runCtx, closeRunCtx := context.WithCancel(context.Background())
	defer closeRunCtx()
	args := append([]string{"run", "-v", "parser_fuzz_test",
		"--no-notifications",
		"--engine-arg=-seed=1",
		"--engine-arg=-runs=1000000"},
		opts.args...)
	cmd := executil.CommandContext(
		runCtx,
		cifuzz,
		args...,
	)
	cmd.Dir = dir
	cmd.Env = opts.env
	stdoutPipe, err := cmd.StdoutTeePipe(os.Stdout)
	require.NoError(t, err)
	stderrPipe, err := cmd.StderrTeePipe(os.Stderr)
	require.NoError(t, err)

	// Terminate the cifuzz process when we receive a termination signal
	// (else the test won't stop). An alternative would be to run the
	// command in the foreground, via syscall.SysProcAttr.Foreground,
	// but that's not supported on Windows.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	go func() {
		s := <-sigs
		t.Logf("Received %s", s.String())
		err = cmd.TerminateProcessGroup()
		require.NoError(t, err)
	}()

	t.Logf("Command: %s", cmd.String())
	err = cmd.Start()
	require.NoError(t, err)

	waitErrCh := make(chan error)
	// Wait for the command to exit in a go routine, so that below
	// we can cancel waiting when the context is done
	go func() {
		waitErrCh <- cmd.Wait()
	}()

	// Check that the output contains the expected output
	var seenExpectedOutputs int
	lenExpectedOutputs := len(opts.expectedOutputs)
	mutex := sync.Mutex{}

	routines := errgroup.Group{}
	routines.Go(func() error {
		// cifuzz progress messages go to stdout.
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			mutex.Lock()
			var remainingExpectedOutputs []*regexp.Regexp
			for _, expectedOutput := range opts.expectedOutputs {
				if expectedOutput.MatchString(scanner.Text()) {
					seenExpectedOutputs += 1
				} else {
					remainingExpectedOutputs = append(remainingExpectedOutputs, expectedOutput)
				}
			}
			opts.expectedOutputs = remainingExpectedOutputs
			if seenExpectedOutputs == lenExpectedOutputs && opts.terminateAfterExpectedOutput {
				err = cmd.TerminateProcessGroup()
				require.NoError(t, err)
			}
			mutex.Unlock()
		}
		err = stdoutPipe.Close()
		require.NoError(t, err)
		return nil
	})

	routines.Go(func() error {
		// Fuzzer output goes to stderr.
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			mutex.Lock()
			var remainingExpectedOutputs []*regexp.Regexp
			for _, expectedOutput := range opts.expectedOutputs {
				if expectedOutput.MatchString(scanner.Text()) {
					seenExpectedOutputs += 1
				} else {
					remainingExpectedOutputs = append(remainingExpectedOutputs, expectedOutput)
				}
			}
			opts.expectedOutputs = remainingExpectedOutputs
			if seenExpectedOutputs == lenExpectedOutputs && opts.terminateAfterExpectedOutput {
				err = cmd.TerminateProcessGroup()
				require.NoError(t, err)
			}
			mutex.Unlock()
		}
		err = stderrPipe.Close()
		require.NoError(t, err)
		return nil
	})

	select {
	case waitErr := <-waitErrCh:

		err = routines.Wait()
		require.NoError(t, err)

		seen := seenExpectedOutputs == lenExpectedOutputs
		if seen && opts.terminateAfterExpectedOutput && executil.IsTerminatedExitErr(waitErr) {
			return
		}
		require.NoError(t, waitErr)
	case <-runCtx.Done():
		require.NoError(t, runCtx.Err())
	}

	seen := seenExpectedOutputs == lenExpectedOutputs
	require.True(t, seen, "Did not see %q in fuzzer output", opts.expectedOutputs)
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

func modifyFuzzTestToCallFunction(t *testing.T, fuzzTestPath string) {
	// Modify the fuzz test stub created by `cifuzz create` to actually
	// call a function.

	f, err := os.OpenFile(fuzzTestPath, os.O_RDWR, 0700)
	require.NoError(t, err)
	defer f.Close()
	scanner := bufio.NewScanner(f)
	// At the top of the file we add the required headers
	lines := []string{`#include "parser.h"`}
	var seenBeginningOfFuzzTestFunc bool
	var addedFunctionCall bool
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "FUZZ_TEST(") {
			seenBeginningOfFuzzTestFunc = true
		}
		// Insert the function call at the end of the FUZZ_TEST
		// function, right above the "}".
		if seenBeginningOfFuzzTestFunc && strings.HasPrefix(scanner.Text(), "}") {
			lines = append(lines, "  parse(std::string(reinterpret_cast<const char *>(data), size));")
			addedFunctionCall = true
		}
		lines = append(lines, scanner.Text())
	}
	require.NoError(t, scanner.Err())
	require.True(t, addedFunctionCall)

	// Write the new content of the fuzz test back to file
	_, err = f.Seek(0, io.SeekStart)
	require.NoError(t, err)
	_, err = f.WriteString(strings.Join(lines, "\n"))
	require.NoError(t, err)

	// Add dependency on parser lib to CMakeLists.txt
	cmakeLists := filepath.Join(filepath.Dir(fuzzTestPath), "CMakeLists.txt")
	f, err = os.OpenFile(cmakeLists, os.O_APPEND|os.O_WRONLY, 0700)
	require.NoError(t, err)
	defer f.Close()
	_, err = f.WriteString("target_link_libraries(parser_fuzz_test PRIVATE parser)\n")
	require.NoError(t, err)
}

func testRemoteRun(t *testing.T, dir string, cifuzz string) {
	projectName := "test-project"
	artifactsName := "test-artifacts-123"
	token := "test-token"

	// Start a mock server to handle our requests
	server := shared.StartMockServer(t, projectName, artifactsName)

	tempDir, err := os.MkdirTemp("", "cifuzz-archive-*")
	require.NoError(t, err)
	defer fileutil.Cleanup(tempDir)

	// Create a dictionary
	dictPath := filepath.Join(tempDir, "some_dict")
	err = os.WriteFile(dictPath, []byte("test-dictionary-content"), 0600)
	require.NoError(t, err)

	// Create a seed corpus directory with an empty seed
	seedCorpusDir, err := os.MkdirTemp(tempDir, "seeds-")
	require.NoError(t, err)
	err = fileutil.Touch(filepath.Join(seedCorpusDir, "empty"))
	require.NoError(t, err)

	// Try to start a remote run on our mock server
	cmd := executil.Command(cifuzz, "remote-run",
		"--dict", dictPath,
		"--engine-arg", "arg1",
		"--engine-arg", "arg2",
		"--seed-corpus", seedCorpusDir,
		"--timeout", "100m",
		"--project", projectName,
		"--server", server.Address,
	)
	cmd.Env, err = envutil.Setenv(os.Environ(), "CIFUZZ_API_TOKEN", token)
	require.NoError(t, err)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	t.Logf("Command: %s", cmd.String())
	err = cmd.Run()
	require.NoError(t, err)

	require.True(t, server.ArtifactsUploaded)
	require.True(t, server.RunStarted)
}
