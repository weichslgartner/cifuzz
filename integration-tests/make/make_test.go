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

	"github.com/otiai10/copy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	builderPkg "code-intelligence.com/cifuzz/internal/builder"
	"code-intelligence.com/cifuzz/internal/testutil"
	"code-intelligence.com/cifuzz/util/executil"
	"code-intelligence.com/cifuzz/util/fileutil"
	"code-intelligence.com/cifuzz/util/stringutil"
)

var expectedFinding = regexp.MustCompile(`heap buffer overflow in exploreMe`)
var filteredLine = regexp.MustCompile(`child process \d+ exited`)

func TestIntegration_Make_RunCoverage(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	if runtime.GOOS == "windows" {
		t.Skip("Make support is only available on Unix")
	}
	testutil.RegisterTestDepOnCIFuzz()

	installDir := testutil.InstallCifuzzInTemp(t)
	dir := copyMakeExampleDir(t, filepath.Join("examples", "other"))
	defer fileutil.Cleanup(dir)
	t.Logf("executing make integration test in %s", dir)

	// Run the two fuzz tests and verify that they crash with the expected finding.
	cifuzz := builderPkg.CIFuzzExecutablePath(filepath.Join(installDir, "bin"))
	runFuzzer(t, cifuzz, dir, "my_fuzz_test", expectedFinding)
	createHtmlCoverageReport(t, cifuzz, dir, "my_fuzz_test")
}

func TestIntegration_Make_DetailedCoverage(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	if runtime.GOOS == "windows" {
		t.Skip("Make support is only available on Unix")
	}
	testutil.RegisterTestDepOnCIFuzz()

	installDir := testutil.InstallCifuzzInTemp(t)

	dir := copyMakeExampleDir(t, filepath.Join("integration-tests", "make", "testdata", "coverage"))
	defer fileutil.Cleanup(dir)
	t.Logf("executing make coverage test in %s", dir)

	cifuzz := builderPkg.CIFuzzExecutablePath(filepath.Join(installDir, "bin"))
	createAndVerifyLcovCoverageReport(t, cifuzz, dir)
}

func copyMakeExampleDir(t *testing.T, rootPath string) string {
	dir, err := os.MkdirTemp("", "cifuzz-make-example-")
	require.NoError(t, err)

	// Get the path to the testdata dir
	cwd, err := os.Getwd()
	require.NoError(t, err)
	exampleDir := filepath.Join(cwd, "..", "..", rootPath)

	// Copy the example dir to the temporary directory
	err = copy.Copy(exampleDir, dir)
	require.NoError(t, err)

	return dir
}

func runFuzzer(t *testing.T, cifuzz string, dir string, fuzzTest string, expectedOutput *regexp.Regexp) {
	t.Helper()

	cmd := executil.Command(
		cifuzz,
		"run", fuzzTest,
		"--no-notifications",
		// The crashes are expected to be found quickly.
		"--engine-arg=-runs=1000000",
		"--engine-arg=-seed=1",
	)
	cmd.Dir = dir
	stdoutPipe, err := cmd.StdoutTeePipe(os.Stdout)
	require.NoError(t, err)
	stderrPipe, err := cmd.StderrTeePipe(os.Stderr)
	require.NoError(t, err)

	t.Logf("Command: %s", cmd.String())
	err = cmd.Run()
	require.NoError(t, err)

	// Check that the output contains the expected output
	var seenExpectedOutput bool
	// cifuzz progress messages go to stdout.
	scanner := bufio.NewScanner(stdoutPipe)
	for scanner.Scan() {
		if expectedOutput.MatchString(scanner.Text()) {
			seenExpectedOutput = true
		}
	}
	// Fuzzer output goes to stderr.
	scanner = bufio.NewScanner(stderrPipe)
	for scanner.Scan() {
		if expectedOutput.MatchString(scanner.Text()) {
			seenExpectedOutput = true
		}
		if filteredLine.MatchString(scanner.Text()) {
			require.FailNow(t, "Found line in output which should have been filtered", scanner.Text())
		}
	}
	require.True(t, seenExpectedOutput, "Did not see %q in fuzzer output", expectedOutput.String())
}

func createHtmlCoverageReport(t *testing.T, cifuzz string, dir string, fuzzTest string) {
	t.Helper()

	cmd := executil.Command(cifuzz, "coverage", "-v",
		"--output", fuzzTest+".coverage.html",
		fuzzTest)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	t.Logf("Command: %s", strings.Join(stringutil.QuotedStrings(cmd.Args), " "))
	err := cmd.Run()
	require.NoError(t, err)

	// Check that the coverage report was created
	reportPath := filepath.Join(dir, fuzzTest+".coverage.html")
	require.FileExists(t, reportPath)

	// Check that the coverage report contains coverage for the api.cpp
	// source file, but not for our headers.
	reportBytes, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	report := string(reportBytes)
	require.Contains(t, report, "explore_me.cpp")
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
			if strings.HasSuffix(line, "/crashing_fuzz_test.cpp") {
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
