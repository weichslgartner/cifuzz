package gradle

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/integration-tests/shared"
	builderPkg "code-intelligence.com/cifuzz/internal/builder"
	"code-intelligence.com/cifuzz/pkg/parser/libfuzzer/stacktrace"
	"code-intelligence.com/cifuzz/util/fileutil"
)

func TestIntegration_Gradle_InitCreateRun(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	if runtime.GOOS == "windows" {
		t.Skip("Running Jazzer is currently broken on our Windows GitHub Action runner")
	}

	// Create installation builder
	installDir := shared.InstallCIFuzzInTemp(t)
	cifuzz := builderPkg.CIFuzzExecutablePath(filepath.Join(installDir, "bin"))

	// Copy testdata
	projectDir := shared.CopyTestdataDir(t, "gradle")
	defer fileutil.Cleanup(projectDir)

	cifuzzRunner := shared.CIFuzzRunner{
		CIFuzzPath:      cifuzz,
		DefaultWorkDir:  projectDir,
		DefaultFuzzTest: "com.example.FuzzTestCase",
	}

	// Execute the init command
	linesToAdd := cifuzzRunner.Command(t, "init", nil)
	assert.FileExists(t, filepath.Join(projectDir, "cifuzz.yaml"))
	shared.AddLinesToFileAtBreakPoint(t, filepath.Join(projectDir, "build.gradle"), linesToAdd, "dependencies", true)

	// Execute the create command
	testDir := filepath.Join(
		"src",
		"test",
		"java",
		"com",
		"example",
	)
	err := os.MkdirAll(filepath.Join(projectDir, testDir), 0755)
	require.NoError(t, err)
	outputPath := filepath.Join(testDir, "FuzzTestCase.java")
	cifuzzRunner.Command(t, "create", &shared.CommandOptions{
		Args: []string{"java", "--output", outputPath}},
	)

	// Check that the fuzz test was created in the correct directory
	fuzzTestPath := filepath.Join(projectDir, outputPath)
	require.FileExists(t, fuzzTestPath)

	// Check that the findings command doesn't list any findings yet
	findings := shared.GetFindings(t, cifuzz, projectDir)
	require.Empty(t, findings)

	// Run the (empty) fuzz test
	cifuzzRunner.Run(t, &shared.RunOptions{
		ExpectedOutputs:              []*regexp.Regexp{regexp.MustCompile(`^paths: \d+`)},
		TerminateAfterExpectedOutput: true,
	})

	// Make the fuzz test call a function
	modifyFuzzTestToCallFunction(t, fuzzTestPath)
	// Run the fuzz test
	expectedOutputExp := regexp.MustCompile(`High: Remote Code Execution`)
	cifuzzRunner.Run(t, &shared.RunOptions{
		ExpectedOutputs: []*regexp.Regexp{expectedOutputExp},
	})

	// Check that the findings command lists the finding
	findings = shared.GetFindings(t, cifuzz, projectDir)
	require.Len(t, findings, 1)
	require.Contains(t, findings[0].Details, "Remote Code Execution")

	//// TODO: This check currently fails on macOS because there
	//// llvm-symbolizer doesn't read debug info from object files.
	//// See https://github.com/google/sanitizers/issues/207#issuecomment-136495556
	if runtime.GOOS != "darwin" {
		expectedStackTrace := []*stacktrace.StackFrame{
			{
				SourceFile:  "com.example.ExploreMe",
				Line:        13,
				Column:      0,
				FrameNumber: 0,
				Function:    "exploreMe",
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
	err = os.WriteFile(filepath.Join(projectDir, "cifuzz.yaml"), []byte(configFileContent), 0644)
	require.NoError(t, err)
	// When minijail is used, the artifact prefix is set to the minijail
	// output path
	cifuzzRunner.Run(t, &shared.RunOptions{
		ExpectedOutputs: []*regexp.Regexp{regexp.MustCompile(`artifact_prefix='./'`)},
	})

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
	err = os.WriteFile(filepath.Join(projectDir, "cifuzz.yaml"), nil, 0644)
	require.NoError(t, err)
}

func modifyFuzzTestToCallFunction(t *testing.T, fuzzTestPath string) {
	// Modify the fuzz test stub created by `cifuzz create` to actually
	// call a function.

	f, err := os.OpenFile(fuzzTestPath, os.O_RDWR, 0700)
	require.NoError(t, err)
	defer f.Close()
	scanner := bufio.NewScanner(f)

	var lines []string
	var seenBeginningOfFuzzTestFunc bool
	var addedFunctionCall bool
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "    @FuzzTest") {
			seenBeginningOfFuzzTestFunc = true
		}
		// Insert the function call at the end of the myFuzzTest
		// function, right above the "}".
		if seenBeginningOfFuzzTestFunc && strings.HasPrefix(scanner.Text(), "    }") {
			lines = append(lines, []string{
				"        int a = data.consumeInt();",
				"        int b = data.consumeInt();",
				"        String c = data.consumeRemainingAsString();",
				"        ExploreMe.exploreMe(a, b, c);",
			}...)
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
}
