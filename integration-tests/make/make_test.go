package cmake

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/otiai10/copy"
	"github.com/stretchr/testify/require"

	builderPkg "code-intelligence.com/cifuzz/internal/builder"
	"code-intelligence.com/cifuzz/util/executil"
	"code-intelligence.com/cifuzz/util/fileutil"
	"code-intelligence.com/cifuzz/util/stringutil"
	"code-intelligence.com/cifuzz/util/testutil"
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

	// Create installation builder
	projectDir, err := builderPkg.FindProjectDir()
	require.NoError(t, err)
	targetDir := filepath.Join(projectDir, "cmd", "installer", "build")
	err = os.RemoveAll(targetDir)
	require.NoError(t, err)

	opts := builderPkg.Options{Version: "dev", TargetDir: targetDir}
	builder, err := builderPkg.NewCIFuzzBuilder(opts)
	defer builder.Cleanup()
	require.NoError(t, err)
	err = builder.BuildCIFuzzAndDeps()
	require.NoError(t, err)

	// Install CIFuzz in temp folder
	installDir, err := os.MkdirTemp("", "cifuzz-")
	require.NoError(t, err)
	defer fileutil.Cleanup(installDir)
	installDir = filepath.Join(installDir, "cifuzz")
	installer := filepath.Join("cmd", "installer", "installer.go")
	installCmd := exec.Command("go", "run", "-tags", "installer", installer, "-i", installDir)
	installCmd.Stderr = os.Stderr
	installCmd.Dir = projectDir
	t.Logf("Command: %s", installCmd.String())
	err = installCmd.Run()
	require.NoError(t, err)

	dir := copyMakeExampleDir(t)
	defer fileutil.Cleanup(dir)
	t.Logf("executing make integration test in %s", dir)

	// Run the two fuzz tests and verify that they crash with the expected finding.
	cifuzz := builderPkg.CIFuzzExecutablePath(filepath.Join(installDir, "bin"))
	runFuzzer(t, cifuzz, dir, "my_fuzz_test", expectedFinding)
	createCoverageReport(t, cifuzz, dir, "my_fuzz_test")
}

func copyMakeExampleDir(t *testing.T) string {
	dir, err := os.MkdirTemp("", "cifuzz-make-example-")
	require.NoError(t, err)

	// Get the path to the testdata dir
	cwd, err := os.Getwd()
	require.NoError(t, err)
	exampleDir := filepath.Join(cwd, "..", "..", "examples", "other")

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

func createCoverageReport(t *testing.T, cifuzz string, dir string, fuzzTest string) {
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
