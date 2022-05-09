package run

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"code-intelligence.com/cifuzz/pkg/cmdutils"
	"code-intelligence.com/cifuzz/pkg/storage"
)

func TestRunCmd(t *testing.T) {
	fs := storage.NewMemFileSystem()
	_, err := cmdutils.ExecuteCommand(t, New(fs), os.Stdin)
	assert.Error(t, err)
}
