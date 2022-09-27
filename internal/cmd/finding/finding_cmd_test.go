package finding

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	initCmd "code-intelligence.com/cifuzz/internal/cmd/init"
	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/internal/testutil"
	"code-intelligence.com/cifuzz/pkg/finding"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/util/stringutil"
)

var logOutput io.ReadWriter

func TestMain(m *testing.M) {
	logOutput = bytes.NewBuffer([]byte{})
	log.Output = logOutput

	m.Run()
}

func TestListFindings(t *testing.T) {
	// Create an empty project directory
	projectDir, cleanup := testutil.ChdirToTempDir("test-list-findings-")
	defer cleanup()

	// Check that the command produces the expected error when not
	// called below a cifuzz project directory.
	_, err := cmdutils.ExecuteCommand(t, New(), os.Stdin)
	require.Error(t, err)
	testutil.CheckOutput(t, logOutput, "set up a project for use with cifuzz")

	// Initialize a cifuzz project
	_, err = cmdutils.ExecuteCommand(t, initCmd.New(), os.Stdin)
	require.NoError(t, err)

	// Check that the command lists no findings in the empty project
	output, err := cmdutils.ExecuteCommand(t, New(), os.Stdin, "--json")
	require.NoError(t, err)
	require.Equal(t, "[]", output)

	// Create a finding
	f := &finding.Finding{Name: "test_finding"}
	err = f.Save(projectDir)
	require.NoError(t, err)

	// Check that the command lists the finding
	output, err = cmdutils.ExecuteCommand(t, New(), os.Stdin, "--json")
	require.NoError(t, err)
	jsonString, err := stringutil.ToJsonString([]*finding.Finding{f})
	require.NoError(t, err)
	require.Equal(t, jsonString, output)
}

func TestPrintFinding(t *testing.T) {
	f := &finding.Finding{Name: "test_finding"}

	// Create an empty project directory
	projectDir, cleanup := testutil.ChdirToTempDir("test-print-finding-")
	defer cleanup()

	// Check that the command produces the expected error when not
	// called below a cifuzz project directory.
	_, err := cmdutils.ExecuteCommand(t, New(), os.Stdin, f.Name, "--json")
	require.Error(t, err)
	testutil.CheckOutput(t, logOutput, "set up a project for use with cifuzz")

	// Initialize a cifuzz project
	_, err = cmdutils.ExecuteCommand(t, initCmd.New(), os.Stdin)
	require.NoError(t, err)

	// Check that the command produces the expected error when the
	// specified finding does not exist
	_, err = cmdutils.ExecuteCommand(t, New(), os.Stdin, f.Name, "--json")
	require.Error(t, err)
	testutil.CheckOutput(t, logOutput, fmt.Sprintf("Finding %s does not exist", f.Name))

	// Create the finding
	err = f.Save(projectDir)
	require.NoError(t, err)

	// Check that the command prints the finding
	output, err := cmdutils.ExecuteCommand(t, New(), os.Stdin, f.Name, "--json")
	require.NoError(t, err)
	jsonString, err := stringutil.ToJsonString(f)
	require.NoError(t, err)
	require.Equal(t, jsonString, output)
}

func TestPrintAllFindings(t *testing.T) {
	var err error

	// Create an empty project directory
	projectDir, cleanup := testutil.ChdirToTempDir("test-print-finding-")
	defer cleanup()

	// Initialize a cifuzz project
	_, err = cmdutils.ExecuteCommand(t, initCmd.New(), os.Stdin)
	require.NoError(t, err)

	// Check that the command lists no findings in the empty project
	output, err := cmdutils.ExecuteCommand(t, New(), os.Stdin, "--all")
	require.NoError(t, err)
	require.Empty(t, output)
	testutil.CheckOutput(t, logOutput, "This project doesn't have any findings yet")

	// Create two findings
	findings := []*finding.Finding{
		{Name: "test_finding1"},
		{Name: "test_finding2"},
	}
	for _, f := range findings {
		err = f.Save(projectDir)
		require.NoError(t, err)
	}

	// Check that the command prints the findings
	output, err = cmdutils.ExecuteCommand(t, New(), os.Stdin, "--all")
	require.NoError(t, err)
	for _, f := range findings {
		require.Contains(t, output, f.Name)
	}
}
