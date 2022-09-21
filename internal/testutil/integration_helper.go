package testutil

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/otiai10/copy"
	"github.com/stretchr/testify/require"

	builderPkg "code-intelligence.com/cifuzz/internal/builder"
	"code-intelligence.com/cifuzz/util/executil"
)

// CopyTestdataDir copies the "testdata" folder in the current working directory
// to a temporary directory called "cifuzz-<name>-testdata" and returns the path.
func CopyTestdataDir(t *testing.T, name string) string {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	dir, err := os.MkdirTemp("", fmt.Sprintf("cifuzz-%s-testdata-", name))
	require.NoError(t, err)

	// Get the path to the testdata dir
	testDataDir := filepath.Join(cwd, "testdata")

	// Copy the testdata dir to the temporary directory
	err = copy.Copy(testDataDir, dir)
	require.NoError(t, err)

	return dir
}

// AddLinesToFileAtBreakPoint adds the given lines before or after the breakpoint
// to the file at the given path.
func AddLinesToFileAtBreakPoint(t *testing.T, filePath string, linesToAdd []string, breakPoint string, addAfterBreakpoint bool) {
	t.Helper()

	f, err := os.OpenFile(filePath, os.O_RDWR, 0700)
	require.NoError(t, err)
	defer f.Close()

	// Add lines to pom.xml
	scanner := bufio.NewScanner(f)
	var lines []string
	var addedLines bool
	for scanner.Scan() {
		if !addedLines && strings.HasPrefix(scanner.Text(), breakPoint) {
			if addAfterBreakpoint {
				lines = append(lines, scanner.Text())
				lines = append(lines, linesToAdd...)
				addedLines = true
				continue
			}

			lines = append(lines, linesToAdd...)
			addedLines = true
		}
		lines = append(lines, scanner.Text())
	}
	if !addedLines {
		require.FailNow(t, fmt.Sprintf("couldn't find breakpoint %s line in %s", breakPoint, filePath))
	}

	// Write the new content of pom.xml back to filePath
	_, err = f.Seek(0, io.SeekStart)
	require.NoError(t, err)
	_, err = f.WriteString(strings.Join(lines, "\n"))
	require.NoError(t, err)
}

// InstallCifuzzInTemp creates an installation builder and
// installs cifuzz in a temp folder and returns its path.
func InstallCifuzzInTemp(t *testing.T) string {
	t.Helper()

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

	// Install cifuzz
	installDir, err := os.MkdirTemp("", "cifuzz-")
	require.NoError(t, err)
	installDir = filepath.Join(installDir, "cifuzz")
	installer := filepath.Join("cmd", "installer", "installer.go")
	installCmd := exec.Command("go", "run", "-tags", "installer", installer, "-i", installDir)
	installCmd.Stderr = os.Stderr
	installCmd.Dir = projectDir
	t.Logf("Command: %s", installCmd.String())
	err = installCmd.Run()
	require.NoError(t, err)

	return installDir
}

// RunCommand runs "cifuzz <args>" command in the given directory
// and returns the suggested code blocks from the console output.
func RunCommand(t *testing.T, dir, cifuzz string, args []string) []string {
	t.Helper()

	cmd := executil.Command(cifuzz, args...)
	cmd.Dir = dir
	stderrPipe, err := cmd.StderrTeePipe(os.Stderr)
	defer stderrPipe.Close()
	require.NoError(t, err)

	t.Logf("Command: %s", cmd.String())
	err = cmd.Run()
	require.NoError(t, err)

	scanner := bufio.NewScanner(stderrPipe)
	var linesToAdd []string
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "    ") {
			linesToAdd = append(linesToAdd, strings.TrimSpace(scanner.Text()))
		} else if len(linesToAdd) != 0 {
			break
		}
	}

	return linesToAdd
}
