package finding_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/internal/testutil"
	"code-intelligence.com/cifuzz/pkg/finding"
	"code-intelligence.com/cifuzz/util/stringutil"
)

var testBaseDir string

func TestMain(m *testing.M) {
	var cleanup func()
	testBaseDir, cleanup = testutil.ChdirToTempDir("finding-test-")
	defer cleanup()

	m.Run()
}

func TestFinding_Save_LoadFinding(t *testing.T) {
	testDir, err := os.MkdirTemp(testBaseDir, "save-test-")
	require.NoError(t, err)

	f := testFinding()
	findingDir := filepath.Join(testDir, finding.NameFindingsDir, f.Name)
	jsonPath := filepath.Join(findingDir, finding.NameJsonFile)

	err = f.Save(testDir)
	require.NoError(t, err)

	require.DirExists(t, findingDir)
	require.FileExists(t, jsonPath)

	// Check that the JSON file exists and contains the expected content
	bytes, err := os.ReadFile(jsonPath)
	require.NoError(t, err)
	actualJSON := string(bytes)
	expectedJSON, err := stringutil.ToJsonString(f)
	require.NoError(t, err)
	require.Equal(t, expectedJSON, actualJSON)

	// Check that LoadFinding also returns the expected finding
	loadedFinding, err := finding.LoadFinding(testDir, f.Name)
	require.NoError(t, err)
	actualJSON, err = stringutil.ToJsonString(loadedFinding)
	require.NoError(t, err)
	require.Equal(t, expectedJSON, actualJSON)
}

func TestFinding_MoveInputFile(t *testing.T) {
	projectDir, err := os.MkdirTemp(testBaseDir, "move-test-project-dir-")
	require.NoError(t, err)
	seedCorpusDir, err := os.MkdirTemp(testBaseDir, "move-test-seed-corpus-")
	require.NoError(t, err)

	// Create an input file
	testfile := "crash_123_test"
	err = os.WriteFile(testfile, []byte("input"), 0644)
	require.NoError(t, err)

	f := testFinding()
	f.InputFile = testfile
	f.Logs = append(f.Logs, fmt.Sprintf("some surrounding text, %s more text", testfile))
	findingDir := filepath.Join(projectDir, finding.NameFindingsDir, f.Name)

	err = f.MoveInputFile(projectDir, seedCorpusDir)
	require.NoError(t, err)

	// Check that the input file in the finding dir was created
	matches, err := filepath.Glob(filepath.Join(findingDir, finding.NameCrashingInput+"*"))
	require.NoError(t, err)
	require.Len(t, matches, 1)

	// Check that the input file was copied to the seed corpus
	matches, err = filepath.Glob(filepath.Join(seedCorpusDir, f.Name+"*"))
	require.NoError(t, err)
	require.Len(t, matches, 1)

	// Check that the log was updated
	require.Contains(t, f.Logs[2], finding.NameCrashingInput)
}

func TestListFindings(t *testing.T) {
	f := testFinding()

	err := f.Save(testBaseDir)
	require.NoError(t, err)

	// Check that the finding is listed
	findings, err := finding.ListFindings(testBaseDir)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Equal(t, f, findings[0])
}

func testFinding() *finding.Finding {
	return &finding.Finding{
		Name: "test-name",
		Logs: []string{
			"Oops",
			"The application crashed",
		},
	}
}
