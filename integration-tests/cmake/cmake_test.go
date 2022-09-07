package cmake

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/otiai10/copy"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"code-intelligence.com/cifuzz/internal/cmd/run/report_handler/stacktrace"
	"code-intelligence.com/cifuzz/pkg/artifact"
	"code-intelligence.com/cifuzz/pkg/finding"
	"code-intelligence.com/cifuzz/pkg/install"
	"code-intelligence.com/cifuzz/util/envutil"
	"code-intelligence.com/cifuzz/util/executil"
	"code-intelligence.com/cifuzz/util/fileutil"
	"code-intelligence.com/cifuzz/util/testutil"
)

func TestIntegration_CMake_InitCreateRunCoverageBundle(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	testutil.RegisterTestDepOnCIFuzz()

	// Create installation bundle
	projectDir, err := install.FindProjectDir()
	require.NoError(t, err)
	targetDir := filepath.Join(projectDir, "tools", "install", "bundler", "embed", "bundle")
	err = os.RemoveAll(targetDir)
	require.NoError(t, err)

	opts := install.Options{Version: "dev", TargetDir: targetDir}
	bundler, err := install.NewInstallationBundler(opts)
	defer bundler.Cleanup()
	require.NoError(t, err)
	err = bundler.BuildCIFuzzAndDeps()
	require.NoError(t, err)

	// Install CIFuzz in temp folder
	installDir, err := os.MkdirTemp("", "cifuzz-")
	require.NoError(t, err)
	installDir = filepath.Join(installDir, "cifuzz")
	installer := filepath.Join("tools", "install", "installer", "installer.go")
	installCmd := exec.Command("go", "run", "-tags", "installer", installer, "-i", installDir)
	installCmd.Stderr = os.Stderr
	installCmd.Dir = projectDir
	t.Logf("Command: %s", installCmd.String())
	err = installCmd.Run()
	require.NoError(t, err)

	err = os.Setenv("CMAKE_PREFIX_PATH", installDir)
	require.NoError(t, err)

	dir := copyTestdataDir(t)
	defer fileutil.Cleanup(dir)
	t.Logf("executing cmake integration test in %s", dir)

	// Execute the root command
	cifuzz := install.CIFuzzExecutablePath(filepath.Join(installDir, "bin"))
	cmd := executil.Command(cifuzz)
	cmd.Dir = dir
	cmd.Stderr = os.Stderr
	t.Logf("Command: %s", cmd.String())
	err = cmd.Run()
	require.NoError(t, err)

	// Execute the init command
	cmd = executil.Command(cifuzz, "init", "-C", dir)
	cmd.Dir = dir
	stderrPipe, err := cmd.StderrTeePipe(os.Stderr)
	require.NoError(t, err)
	t.Logf("Command: %s", cmd.String())
	err = cmd.Run()
	require.NoError(t, err)
	followStepsPrintedByInitCommand(t, stderrPipe, filepath.Join(dir, "CMakeLists.txt"))
	err = stderrPipe.Close()
	require.NoError(t, err)

	// Execute the create command
	outputPath := filepath.Join("src", "parser", "parser_fuzz_test.cpp")
	cmd = executil.Command(cifuzz, "create", "-C", dir, "cpp", "--output", outputPath)
	cmd.Dir = dir
	stderrPipe, err = cmd.StderrTeePipe(os.Stderr)
	require.NoError(t, err)
	cmd.Stdout = os.Stdout
	require.NoError(t, err)
	t.Logf("Command: %s", cmd.String())
	err = cmd.Run()
	require.NoError(t, err)

	// Check that the fuzz test was created in the correct directory
	fuzzTestPath := filepath.Join(dir, outputPath)
	require.FileExists(t, fuzzTestPath)
	followStepsPrintedByCreateCommand(t, stderrPipe, filepath.Join(filepath.Dir(fuzzTestPath), "CMakeLists.txt"))
	err = stderrPipe.Close()
	require.NoError(t, err)

	// Check that the findings command doesn't list any findings yet
	findings := getFindings(t, cifuzz, dir)
	require.Empty(t, findings)

	// Run the (empty) fuzz test
	runFuzzer(t, cifuzz, dir, &runFuzzerOptions{
		expectedOutput:               regexp.MustCompile(`^paths: \d+`),
		terminateAfterExpectedOutput: true,
	})

	// Make the fuzz test call a function. Before we do that, we sleep
	// for one second, to avoid make implementations which only look at
	// the full seconds of the timestamp to not rebuild the target, see
	// https://www.gnu.org/software/autoconf/manual/autoconf-2.63/html_node/Timestamps-and-Make.html
	time.Sleep(time.Second)
	modifyFuzzTestToCallFunction(t, fuzzTestPath)
	// Run the fuzz test
	runFuzzer(t, cifuzz, dir, &runFuzzerOptions{
		expectedOutput: regexp.MustCompile(`^==\d*==ERROR: AddressSanitizer: heap-use-after-free`),
	})

	// Check that the findings command lists the finding
	findings = getFindings(t, cifuzz, dir)
	require.Len(t, findings, 1)
	require.Contains(t, findings[0].Details, "heap-use-after-free")
	// TODO: This check currently fails on macOS because there
	// llvm-symbolizer doesn't read debug info from object files.
	// See https://github.com/google/sanitizers/issues/207#issuecomment-136495556
	if runtime.GOOS != "darwin" {
		expectedStackTrace := []*stacktrace.StackFrame{
			{
				SourceFile:  "src/parser/parser.cpp",
				Line:        19,
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

		require.Equal(t, expectedStackTrace, findings[0].StackTrace)
	}

	// Check that options set via the config file are respected
	configFileContent := `use-sandbox: false`
	err = os.WriteFile(filepath.Join(dir, "cifuzz.yaml"), []byte(configFileContent), 0644)
	// When minijail is used, the artifact prefix is set to the minijail
	// output path
	runFuzzer(t, cifuzz, dir, &runFuzzerOptions{
		expectedOutput: regexp.MustCompile(`artifact_prefix='./'`),
	})

	if runtime.GOOS == "linux" {
		// Check that command-line flags take precedence over config file
		// settings (only on Linux because we only support Minijail on
		// Linux).
		runFuzzer(t, cifuzz, dir, &runFuzzerOptions{
			expectedOutput: regexp.MustCompile(`minijail`),
			args:           []string{"--use-sandbox=true"},
		})
	}

	// Check that ASAN_OPTIONS can be set
	env, err := envutil.Setenv(os.Environ(), "ASAN_OPTIONS", "print_stats=1:atexit=1")
	require.NoError(t, err)
	runFuzzer(t, cifuzz, dir, &runFuzzerOptions{
		expectedOutput:               regexp.MustCompile(`Stats:`),
		terminateAfterExpectedOutput: false,
		env:                          env,
	})

	// Building with coverage instrumentation doesn't work on Windows yet
	if runtime.GOOS != "windows" {
		// Produce a coverage report for the fuzz test
		createCoverageReport(t, cifuzz, dir)
	}

	// Run cifuzz bundle and verify the contents of the archive.
	archiveDir := createAndExtractArtifactArchive(t, dir, cifuzz)
	defer fileutil.Cleanup(archiveDir)
	runArchivedFuzzer(t, archiveDir)
}

func copyTestdataDir(t *testing.T) string {
	dir, err := os.MkdirTemp("", "cifuzz-cmake-testdata-")
	require.NoError(t, err)

	// Get the path to the testdata dir
	cwd, err := os.Getwd()
	require.NoError(t, err)
	testDataDir := filepath.Join(cwd, "testdata")

	// Copy the testdata dir to the temporary directory
	err = copy.Copy(testDataDir, dir)
	require.NoError(t, err)

	return dir
}

type runFuzzerOptions struct {
	expectedOutput               *regexp.Regexp
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
	seenExpectedOutput := &atomic.Value{}
	seenExpectedOutput.Store(false)

	routines := errgroup.Group{}
	routines.Go(func() error {
		// cifuzz progress messages go to stdout.
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			if opts.expectedOutput.MatchString(scanner.Text()) {
				seenExpectedOutput.Store(true)
				if opts.terminateAfterExpectedOutput {
					err = cmd.TerminateProcessGroup()
					require.NoError(t, err)
				}
			}
		}
		err = stdoutPipe.Close()
		require.NoError(t, err)
		return nil
	})

	routines.Go(func() error {
		// Fuzzer output goes to stderr.
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			if opts.expectedOutput.MatchString(scanner.Text()) {
				seenExpectedOutput.Store(true)
				if opts.terminateAfterExpectedOutput {
					err = cmd.TerminateProcessGroup()
					require.NoError(t, err)
				}
			}
		}
		err = stderrPipe.Close()
		require.NoError(t, err)
		return nil
	})

	select {
	case waitErr := <-waitErrCh:

		err = routines.Wait()
		require.NoError(t, err)

		seen := seenExpectedOutput.Load().(bool)
		if seen && opts.terminateAfterExpectedOutput && executil.IsTerminatedExitErr(waitErr) {
			return
		}
		require.NoError(t, waitErr)
	case <-runCtx.Done():
		require.NoError(t, runCtx.Err())
	}

	seen := seenExpectedOutput.Load().(bool)
	require.True(t, seen, "Did not see %q in fuzzer output", opts.expectedOutput.String())
}

func createCoverageReport(t *testing.T, cifuzz string, dir string) {
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
	// parser.cpp source file
	bytes, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	require.Contains(t, string(bytes), "parser.cpp")
}

func followStepsPrintedByInitCommand(t *testing.T, initOutput io.Reader, cmakeLists string) {
	t.Helper()

	// Enable fuzz testing by adding to CMakeLists.txt the lines which
	// `cifuzz init` tells us to add

	// First, parse the `cifuzz init` output to find the lines we should
	// add to CMakeLists.txt - the first indented block.
	scanner := bufio.NewScanner(initOutput)
	var linesToAdd []string
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "    ") {
			linesToAdd = append(linesToAdd, strings.TrimSpace(scanner.Text()))
		} else if len(linesToAdd) != 0 {
			break
		}
	}
	if len(linesToAdd) == 0 {
		require.FailNow(t, "`cictl init` didn't print the lines which should be added to CMakeLists.txt")
	}
	f, err := os.OpenFile(cmakeLists, os.O_RDWR, 0700)
	require.NoError(t, err)
	defer f.Close()

	// Now find the correct line in CMakeLists.txt where the lines
	// should be added. It must be before any "add_subdirectory"
	// functions which add directories that might use functions from
	// the cifuzz CMake package.
	scanner = bufio.NewScanner(f)
	var lines []string
	var addedLines bool
	for scanner.Scan() {
		if !addedLines && strings.HasPrefix(scanner.Text(), "add_subdirectory") {
			// Found an "add_subdirectory" call, insert the lines before
			// that line
			lines = append(lines, linesToAdd...)
			addedLines = true
		}
		lines = append(lines, scanner.Text())
	}
	if !addedLines {
		require.FailNow(t, "Didn't find a \"add_subdirectory\" line in %v", cmakeLists)
	}

	// Write the new content of CMakeLists.txt back to file
	_, err = f.Seek(0, io.SeekStart)
	require.NoError(t, err)
	_, err = f.WriteString(strings.Join(lines, "\n"))
	require.NoError(t, err)
}

func followStepsPrintedByCreateCommand(t *testing.T, initOutput io.Reader, cmakeLists string) {
	t.Helper()

	// Create a CMake target for the fuzz test by adding to
	// CMakeLists.txt the lines which `cifuzz create` tells us to add

	// Parse the `cifuzz create` output to find the lines we should add
	// to CMakeLists.txt
	scanner := bufio.NewScanner(initOutput)
	var cMakeListsSuffix []byte
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "    ") {
			line := strings.TrimSpace(scanner.Text()) + "\n"
			cMakeListsSuffix = append(cMakeListsSuffix, []byte(line)...)
		}
	}
	if len(cMakeListsSuffix) == 0 {
		require.FailNow(t, "`cictl create` didn't print the lines which should be added to CMakeLists.txt")
	}

	// Append the lines to CMakeLists.txt
	f, err := os.OpenFile(cmakeLists, os.O_APPEND|os.O_WRONLY, 0700)
	require.NoError(t, err)
	defer f.Close()
	_, err = f.Write(cMakeListsSuffix)
	require.NoError(t, err)
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

func createAndExtractArtifactArchive(t *testing.T, dir string, cifuzz string) string {
	tempDir, err := os.MkdirTemp("", "cifuzz-archive-*")
	require.NoError(t, err)
	defer fileutil.Cleanup(tempDir)
	archivePath := filepath.Join(tempDir, "parser_fuzz_test.tar.gz")

	// Create a dictionary
	dictPath := filepath.Join(tempDir, "some_dict")
	err = os.WriteFile(dictPath, []byte("test-dictionary-content"), 0600)
	require.NoError(t, err)

	// Create a seed corpus directory with an empty seed
	seedCorpusDir, err := os.MkdirTemp(tempDir, "seeds-")
	require.NoError(t, err)
	err = fileutil.Touch(filepath.Join(seedCorpusDir, "empty"))
	require.NoError(t, err)

	// Bundle all fuzz tests into an archive.
	cmd := executil.Command(cifuzz, "bundle",
		"-o", archivePath,
		"--dict", dictPath,
		"--seed-corpus", seedCorpusDir,
	)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	require.NoError(t, err)
	require.FileExists(t, archivePath)

	// Extract the archive into a new temporary directory.
	archiveDir, err := os.MkdirTemp("", "cifuzz-extracted-archive-*")
	require.NoError(t, err)
	archiveFile, err := os.Open(archivePath)
	require.NoError(t, err)
	err = artifact.ExtractArchiveForTestsOnly(archiveFile, archiveDir)
	require.NoError(t, err)
	return archiveDir
}

func runArchivedFuzzer(t *testing.T, archiveDir string) {
	// Read the fuzzer path from the YAML.
	metadataPath := filepath.Join(archiveDir, "cifuzz.yaml")
	require.FileExists(t, metadataPath)
	metadataYaml, err := os.ReadFile(metadataPath)
	require.NoError(t, err)
	// We use a simple regex here instead of duplicating knowledge of our metadata YAML schema.
	fuzzerPathPattern := regexp.MustCompile(`\W*path: (.*address.*parser_fuzz_test.*)`)
	fuzzerPath := filepath.Join(archiveDir, string(fuzzerPathPattern.FindSubmatch(metadataYaml)[1]))
	require.FileExists(t, fuzzerPath)

	// Run the fuzzer on the empty input to verify that it finds all its runtime dependencies.
	cmd := executil.Command(fuzzerPath, "-runs=0")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// NO_CIFUZZ is set on the backend via engine_options.
	cmd.Env = append(os.Environ(), "NO_CIFUZZ=1")
	err = cmd.Run()
	require.NoError(t, err)

	// Verify that the dictionary has been packaged with the fuzzer.
	dictPattern := regexp.MustCompile(`\W*dictionary: (.*)`)
	dictPath := filepath.Join(archiveDir, string(dictPattern.FindSubmatch(metadataYaml)[1]))
	require.FileExists(t, dictPath)
	content, err := os.ReadFile(dictPath)
	require.NoError(t, err)
	require.Equal(t, "test-dictionary-content", string(content))

	// Verify that the seed corpus has been packaged with the fuzzer. Only parser_fuzz_test has a corpus, so we can
	// use the only matched line.
	seedCorpusPattern := regexp.MustCompile(`\W*seeds: (.*)`)
	seedCorpusPath := filepath.Join(archiveDir, string(seedCorpusPattern.FindSubmatch(metadataYaml)[1]))
	require.DirExists(t, seedCorpusPath)
	require.FileExists(t, filepath.Join(seedCorpusPath, "some_seed"))
	// Check that the empty seed from the user-specified seed corpus
	// was copied into the archive
	require.FileExists(t, filepath.Join(seedCorpusPath, "empty"))

	if runtime.GOOS == "windows" {
		// There are no coverage builds on Windows.
		return
	}
	// Verify that a coverage build has been added to the archive.
	fuzzerPathPattern = regexp.MustCompile(`\W*path: (replayer/coverage.*parser_fuzz_test.*)`)
	fuzzerPath = filepath.Join(archiveDir, string(fuzzerPathPattern.FindSubmatch(metadataYaml)[1]))
	require.FileExists(t, fuzzerPath)

	// Run the coverage build, which uses the replayer, on the seed corpus and verify that it creates a coverage
	// profile.
	coverageProfile := filepath.Join(archiveDir, "profile.lcov")
	cmd = executil.Command(fuzzerPath, seedCorpusPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "LLVM_PROFILE_FILE="+coverageProfile)
	err = cmd.Run()
	require.NoError(t, err)
	require.FileExists(t, coverageProfile)
}

func getFindings(t *testing.T, cifuzz string, dir string) []*finding.Finding {
	cmd := executil.Command(cifuzz, "findings", "--json")
	cmd.Dir = dir
	output, err := cmd.Output()
	require.NoError(t, err)

	var findings []*finding.Finding
	err = json.Unmarshal(output, &findings)
	require.NoError(t, err)
	return findings
}
