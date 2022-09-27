package init

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/internal/testutil"
)

func TestMain(m *testing.M) {
	_, cleanup := testutil.ChdirToTempDir("init-cmd-test-")
	defer cleanup()

	m.Run()
}

func TestInitCmd(t *testing.T) {
	_, err := cmdutils.ExecuteCommand(t, New(), os.Stdin)
	assert.NoError(t, err)

	// second execution should return a ErrSilent as the config file should aready exists
	_, err = cmdutils.ExecuteCommand(t, New(), os.Stdin)
	assert.Error(t, err)
	assert.ErrorIs(t, err, cmdutils.ErrSilent)
}
