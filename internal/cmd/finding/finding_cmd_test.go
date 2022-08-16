package finding

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	initCmd "code-intelligence.com/cifuzz/internal/cmd/init"
	"code-intelligence.com/cifuzz/pkg/cmdutils"
	"code-intelligence.com/cifuzz/pkg/finding"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/util/fileutil"
	"code-intelligence.com/cifuzz/util/stringutil"
	"code-intelligence.com/cifuzz/util/testutil"
)

var logOutput io.ReadWriter

func TestMain(m *testing.M) {
	logOutput = bytes.NewBuffer([]byte{})
	log.Output = logOutput

	m.Run()
}

func TestListFindings(t *testing.T) {
	// Create an empty project directory
	projectDir := testutil.ChdirToTempDir("test-list-findings-")
	defer fileutil.Cleanup(projectDir)

	// Check that the command produces the expected error when not
	// called below a cifuzz project directory.
	_, err := cmdutils.ExecuteCommand(t, New(), os.Stdin)
	require.Error(t, err)
	checkOutput(t, logOutput, "set up a project for use with cifuzz")

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
	projectDir := testutil.ChdirToTempDir("test-print-finding-")
	defer fileutil.Cleanup(projectDir)

	// Check that the command produces the expected error when not
	// called below a cifuzz project directory.
	_, err := cmdutils.ExecuteCommand(t, New(), os.Stdin, f.Name, "--json")
	require.Error(t, err)
	checkOutput(t, logOutput, "set up a project for use with cifuzz")

	// Initialize a cifuzz project
	_, err = cmdutils.ExecuteCommand(t, initCmd.New(), os.Stdin)
	require.NoError(t, err)

	// Check that the command produces the expected error when the
	// specified finding does not exist
	_, err = cmdutils.ExecuteCommand(t, New(), os.Stdin, f.Name, "--json")
	require.Error(t, err)
	checkOutput(t, logOutput, fmt.Sprintf("Finding %s does not exist", f.Name))

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

func checkOutput(t *testing.T, r io.Reader, s ...string) {
	output, err := io.ReadAll(r)
	require.NoError(t, err)
	for _, str := range s {
		require.Contains(t, string(output), str)
	}
}
