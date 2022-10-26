package shared

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/util/envutil"
	"code-intelligence.com/cifuzz/util/executil"
	"code-intelligence.com/cifuzz/util/fileutil"
)

func TestRemoteRun(t *testing.T, dir string, cifuzz string, args ...string) {
	projectName := "test-project"
	artifactsName := "test-artifacts-123"
	token := "test-token"

	// Start a mock server to handle our requests
	server := StartMockServer(t, projectName, artifactsName)

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
	args = append(
		[]string{
			"remote-run",
			"--dict", dictPath,
			"--engine-arg", "arg1",
			"--engine-arg", "arg2",
			"--seed-corpus", seedCorpusDir,
			"--timeout", "100m",
			"--project", projectName,
			"--server", server.Address,
		}, args...)
	cmd := executil.Command(cifuzz, args...)
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
