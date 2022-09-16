package access_tokens

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/util/fileutil"
)

func TestGetAndSet(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "access-tokens-test-")
	require.NoError(t, err)
	defer fileutil.Cleanup(tempDir)
	accessTokensFilePath = filepath.Join(tempDir, "access_tokens.json")
	accessTokens = map[string]string{}

	token := Get("http://localhost:8000")
	require.Empty(t, token)

	err = Set("http://localhost:8000", "token")
	require.NoError(t, err)

	token = Get("http://localhost:8000")
	require.Equal(t, "token", token)

	err = Set("http://localhost:8000", "token2")
	require.NoError(t, err)

	token = Get("http://localhost:8000")
	require.NoError(t, err)
	require.Equal(t, "token2", token)
}
